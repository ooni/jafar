package httpproxy

import (
	"bytes"
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
)

func TestIntegrationPass(t *testing.T) {
	server, addr := newproxy(t, "ooni.io")
	// We're filtering ooni.io, so we expect example.com to pass
	// through the proxy with 200 and we also expect to see the
	// Via header in the responses we receive, of course.
	checkrequest(t, addr.String(), "example.com", 200, true)
	killproxy(t, server)
}

func TestIntegrationBlock(t *testing.T) {
	server, addr := newproxy(t, "ooni.io")
	// Here we're filtering any domain containing ooni.io, so we
	// expect the proxy to send 451 without actually proxing, thus
	// there should not be any Via header in the output.
	checkrequest(t, addr.String(), "mia-ps.ooni.io", 451, false)
	killproxy(t, server)
}

func TestIntegrationLoop(t *testing.T) {
	server, addr := newproxy(t, "ooni.io")
	// Here we're forcing the proxy to connect to itself. It does
	// does that and recognizes itself because of the Via header
	// being set in the request generated by the connection to itself,
	// which should cause a 400. The response should have the Via
	// header set because the 400 is received by the connection that
	// this code has made to the proxy.
	checkrequest(t, addr.String(), addr.String(), 400, true)
	killproxy(t, server)
}

func TestIntegrationListenError(t *testing.T) {
	proxy, err := NewCensoringProxy(
		[]string{""}, "dot", "1.1.1.1:853",
	)
	if err != nil {
		t.Fatal(err)
	}
	server, addr, err := proxy.Start("8.8.8.8:80")
	if err == nil {
		t.Fatal("expected an error here")
	}
	if server != nil {
		t.Fatal("expected nil server here")
	}
	if addr != nil {
		t.Fatal("expected nil addr here")
	}
}

func newproxy(t *testing.T, blocked string) (*http.Server, net.Addr) {
	proxy, err := NewCensoringProxy(
		[]string{blocked}, "dot", "1.1.1.1:853",
	)
	if err != nil {
		t.Fatal(err)
	}
	server, addr, err := proxy.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return server, addr
}

func killproxy(t *testing.T, server *http.Server) {
	err := server.Shutdown(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func checkrequest(
	t *testing.T, proxyAddr, host string,
	expectStatus int, expectVia bool,
) {
	req, err := http.NewRequest("GET", "http://"+proxyAddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != expectStatus {
		t.Fatal("unexpected value of status code")
	}
	t.Log(resp)
	values, _ := resp.Header["Via"]
	var foundProduct bool
	for _, value := range values {
		if value == product {
			foundProduct = true
		}
	}
	if foundProduct && !expectVia {
		t.Fatal("unexpectedly found Via header")
	}
	if !foundProduct && expectVia {
		t.Fatal("Via header not found")
	}
	proxiedData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if expectStatus == 200 {
		checkbody(t, proxiedData, host)
	}
}

func checkbody(t *testing.T, proxiedData []byte, host string) {
	resp, err := http.Get("http://" + host)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatal("unexpected status code")
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(data, proxiedData) == false {
		t.Fatal("body mismatch")
	}
}
