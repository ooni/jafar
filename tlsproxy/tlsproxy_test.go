package tlsproxy

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
)

func TestIntegrationPass(t *testing.T) {
	listener := newproxy(t, "ooni.io")
	checkdialtls(t, listener.Addr().String(), true, &tls.Config{
		ServerName: "example.com",
	})
	killproxy(t, listener)
}

func TestIntegrationBlock(t *testing.T) {
	listener := newproxy(t, "ooni.io")
	checkdialtls(t, listener.Addr().String(), false, &tls.Config{
		ServerName: "mia-ps.ooni.io",
	})
	killproxy(t, listener)
}

func TestIntegrationNoSNI(t *testing.T) {
	listener := newproxy(t, "ooni.io")
	checkdialtls(t, listener.Addr().String(), false, &tls.Config{
		ServerName: "",
	})
	killproxy(t, listener)
}

func TestIntegrationInvalidDomain(t *testing.T) {
	listener := newproxy(t, "ooni.io")
	checkdialtls(t, listener.Addr().String(), false, &tls.Config{
		ServerName: "antani.local",
	})
	killproxy(t, listener)
}

func TestIntegrationFailHandshake(t *testing.T) {
	listener := newproxy(t, "ooni.io")
	checkdialtls(t, listener.Addr().String(), false, &tls.Config{
		ServerName: "expired.badssl.com",
	})
	killproxy(t, listener)
}

func TestFailConnectingToSelf(t *testing.T) {
	proxy := &CensoringProxy{
		dial: func(network string, address string) (net.Conn, error) {
			return &mockedConn{}, nil
		},
	}
	listener, err := proxy.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if listener == nil {
		t.Fatal("expected non nil listener here")
	}
	checkdialtls(t, listener.Addr().String(), false, &tls.Config{
		ServerName: "www.google.com",
	})
	killproxy(t, listener)
}

func TestFailWriteAfterConnect(t *testing.T) {
	proxy := &CensoringProxy{
		dial: func(network string, address string) (net.Conn, error) {
			return &mockedConn{
				// must be different or it refuses connecting to self
				localIP:  net.IPv4(127, 0, 0, 1),
				remoteIP: net.IPv4(127, 0, 0, 2),
			}, nil
		},
	}
	listener, err := proxy.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if listener == nil {
		t.Fatal("expected non nil listener here")
	}
	checkdialtls(t, listener.Addr().String(), false, &tls.Config{
		ServerName: "www.google.com",
	})
	killproxy(t, listener)
}

func TestIntegrationListenError(t *testing.T) {
	proxy, err := NewCensoringProxy(
		[]string{""}, "dot", "1.1.1.1:853",
	)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := proxy.Start("8.8.8.8:80")
	if err == nil {
		t.Fatal("expected an error here")
	}
	if listener != nil {
		t.Fatal("expected nil listener here")
	}
}

func newproxy(t *testing.T, blocked string) net.Listener {
	proxy, err := NewCensoringProxy(
		[]string{blocked}, "dot", "1.1.1.1:853",
	)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := proxy.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func killproxy(t *testing.T, listener net.Listener) {
	err := listener.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func checkdialtls(
	t *testing.T, proxyAddr string, expectSuccess bool, config *tls.Config,
) {
	conn, err := tls.Dial("tcp", proxyAddr, config)
	if err != nil && expectSuccess {
		t.Fatal(err)
	}
	if err == nil && !expectSuccess {
		t.Fatal("expected failure here")
	}
	if conn == nil && expectSuccess {
		t.Fatal("expected actionable conn")
	}
	if conn != nil && !expectSuccess {
		t.Fatal("expected nil conn")
	}
	if conn != nil {
		conn.Close()
	}
}

type mockedConn struct {
	net.Conn
	localIP  net.IP
	remoteIP net.IP
}

func (c *mockedConn) Write(b []byte) (int, error) {
	return 0, errors.New("cannot write sorry")
}

func (c *mockedConn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP: c.localIP,
	}
}

func (c *mockedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP: c.remoteIP,
	}
}
