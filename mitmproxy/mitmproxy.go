// Package mitmproxy contains a TLS MITM proxy
package mitmproxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/google/martian/v3/mitm"
)

// CensoringProxy is a TLS MITM proxy
type CensoringProxy struct{}

// NewCensoringProxy creates a new TLS MITM proxy
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

// Start starts the TLS MITM proxy
func (p *CensoringProxy) Start(address string) (net.Listener, *x509.Certificate, error) {
	cert, privkey, err := mitm.NewAuthority(
		"jafar", "OONI", 24*time.Hour,
	)
	if err != nil {
		return nil, nil, err
	}
	config, err := mitm.NewConfig(cert, privkey)
	if err != nil {
		return nil, nil, err
	}
	listener, err := tls.Listen("tcp", address, config.TLS())
	if err != nil {
		return nil, nil, err
	}
	go p.run(listener)
	return listener, cert, nil
}
