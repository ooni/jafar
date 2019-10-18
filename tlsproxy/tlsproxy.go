// Package tlsproxy contains a TLS transparent proxy
package tlsproxy

import (
	"crypto/tls"
	"errors"
	"flag"
	"net"
	"strings"
	"sync"

	"github.com/apex/log"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/ooni/netx"
	"github.com/ooni/netx/handlers"
)

var (
	address = flag.String(
		"tlsproxy-address", "127.0.0.1:443",
		"Address where the TLS transparent proxy should listen",
	)
	blocked flagx.StringArray
)

func init() {
	flag.Var(
		&blocked, "tlsproxy-block",
		"Censor requests via TLS proxy if client hello contains <value>",
	)
}

// handshakeReader is a hack to perform the initial part of the
// TLS handshake so to know the SNI and then replay the bytes of
// this initial part of the handshake with the server.
type handshakeReader struct {
	net.Conn
	incoming []byte
}

// Read saves the initial bytes of the handshake such that later
// we can replay the handshake with the real TLS server.
func (c *handshakeReader) Read(b []byte) (int, error) {
	count, err := c.Conn.Read(b)
	if err == nil {
		c.incoming = append(c.incoming, b[:count]...)
	}
	return count, err
}

// Write prevents writing on the real connection
func (c *handshakeReader) Write(b []byte) (int, error) {
	return 0, errors.New("cannot write on this connection")
}

// Close prevents closing the real connection
func (c *handshakeReader) Close() error {
	return nil
}

// forward forwards left traffic to right
func forward(wg *sync.WaitGroup, left, right net.Conn) {
	data := make([]byte, 1<<18)
	for {
		n, err := left.Read(data)
		if err != nil {
			break
		}
		if _, err = right.Write(data[:n]); err != nil {
			break
		}
	}
	wg.Done()
}

// reset resets the connection
func reset(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	conn.Close()
}

// alertclose sends a TLS alert and then closes the connection
func alertclose(conn net.Conn) {
	alertdata := []byte{
		21, // alert
		3,  // version[0]
		3,  // version[1]
		0,  // length[0]
		2,  // length[1]
		2,  // fatal
		80, // internal error
	}
	conn.Write(alertdata)
	conn.Close()
}

// getsni attempts the handshakeReader hack to obtain the SNI by reading
// the beginning of the TLS handshake. On success a nonempty SNI string
// is returned. Otherwise we cannot distinguish between the absence of a
// SNI and any other reading network error that may have occurred.
func getsni(conn *handshakeReader) string {
	var (
		sni   string
		mutex sync.Mutex // just for safety
	)
	tls.Server(conn, &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mutex.Lock()
			sni = info.ServerName
			mutex.Unlock()
			return nil, errors.New("tlsproxy: we can't really continue handshake")
		},
	}).Handshake()
	return sni
}

// handle implements the TLS SNI proxy
func handle(clientconn net.Conn) {
	hr := &handshakeReader{Conn: clientconn}
	sni := getsni(hr)
	if sni == "" {
		log.Warn("tlsproxy: network failure or SNI not provided")
		reset(clientconn)
		return
	}
	for _, pattern := range blocked {
		if strings.Contains(sni, pattern) {
			log.Warnf("tlsproxy: reject SNI by policy: %s", sni)
			alertclose(clientconn)
			return
		}
	}
	dialer := netx.NewDialer(handlers.StdoutHandler)
	dialer.ConfigureDNS("dot", "1.1.1.1:853")
	serverconn, err := dialer.Dial("tcp", net.JoinHostPort(sni, "443"))
	if err != nil {
		log.WithError(err).Warn("tlsproxy: dialer.Dial failed")
		alertclose(clientconn)
		return
	}
	if _, err := serverconn.Write(hr.incoming); err != nil {
		log.WithError(err).Warn("tlsproxy: serverconn.Write failed")
		alertclose(clientconn)
		return
	}
	log.Infof("tlsproxy: routing for %s", sni)
	defer clientconn.Close()
	defer serverconn.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go forward(&wg, clientconn, serverconn)
	go forward(&wg, serverconn, clientconn)
	wg.Wait()
}

func run() {
	listener, err := net.Listen("tcp", *address)
	rtx.Must(err, "net.Listen failed")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.WithError(err).Warn("listener.Accept failed")
			continue
		}
		go handle(conn)
	}
}

// Start starts the TLS transparent proxy.
func Start() {
	go run()
}
