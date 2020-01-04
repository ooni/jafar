// Package badproxy contains a bad proxy. Specifically this proxy
// will read some bytes from the input and then close the connection.
package badproxy

import (
	"io"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

// CensoringProxy is a bad proxy
type CensoringProxy struct {
	listener net.Listener
}

// NewCensoringProxy creates a new bad proxy
func NewCensoringProxy() *CensoringProxy {
	return new(CensoringProxy)
}

func (p *CensoringProxy) serve(conn net.Conn) {
	deadline := time.Now().Add(250 * time.Millisecond)
	conn.SetDeadline(deadline)
	const maxread = 1 << 17
	reader := io.LimitReader(conn, maxread)
	ioutil.ReadAll(reader)
	conn.Close()
}

func (p *CensoringProxy) run(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil && strings.Contains(
			err.Error(), "use of closed network connection") {
			return
		}
		if err == nil {
			// It's difficult to make accept fail, so restructure
			// the code such that we enter into the happy path
			go p.serve(conn)
		}
	}
}

// Start starts the bad proxy
func (p *CensoringProxy) Start(address string) (net.Listener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	go p.run(listener)
	return listener, nil
}
