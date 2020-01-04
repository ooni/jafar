package badproxy

import (
	"net"
	"testing"
)

func TestIntegrationCommonCase(t *testing.T) {
	listener := newproxy(t, "ooni.io")
	checkdial(t, listener.Addr().String(), true)
	killproxy(t, listener)
}

func TestIntegrationListenError(t *testing.T) {
	proxy := NewCensoringProxy()
	listener, err := proxy.Start("8.8.8.8:80")
	if err == nil {
		t.Fatal("expected an error here")
	}
	if listener != nil {
		t.Fatal("expected nil listener here")
	}
}

func newproxy(t *testing.T, blocked string) net.Listener {
	proxy := NewCensoringProxy()
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

func checkdial(
	t *testing.T, proxyAddr string, expectSuccess bool,
) {
	conn, err := net.Dial("tcp", proxyAddr)
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
		conn.Write([]byte("123454321"))
		conn.Close()
	}
}
