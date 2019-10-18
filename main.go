// jafar is a censorship simulator. We used to have an evilgenius doing
// that but now we're resorting to an even more evil grand viezir.
package main

import (
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/miekg/dns"
	"github.com/ooni/jafar/httpproxy"
	"github.com/ooni/jafar/iptables"
	"github.com/ooni/jafar/resolver"
	"github.com/ooni/jafar/tlsproxy"
)

var (
	dnsProxyAddress      *string
	dnsProxyBlock        flagx.StringArray
	dnsProxyDNSAddress   *string
	dnsProxyDNSTransport *string
	dnsProxyHijack       flagx.StringArray

	httpProxyAddress      *string
	httpProxyBlock        flagx.StringArray
	httpProxyDNSAddress   *string
	httpProxyDNSTransport *string

	tlsProxyAddress      *string
	tlsProxyBlock        flagx.StringArray
	tlsProxyDNSAddress   *string
	tlsProxyDNSTransport *string
)

func init() {
	// dnsProxy
	dnsProxyAddress = flag.String(
		"dns-proxy-address", "127.0.0.1:53",
		"Address where the DNS proxy should listen",
	)
	flag.Var(
		&dnsProxyBlock, "dns-proxy-block",
		"Register keyword triggering NXDOMAIN censorship",
	)
	dnsProxyDNSAddress = flag.String(
		"dns-proxy-dns-address", "1.1.1.1:853",
		"Address of the upstream DNS to be used by the proxy",
	)
	dnsProxyDNSTransport = flag.String(
		"dns-proxy-dns-transport", "dot",
		"Transport to be used with the upstream DNS",
	)
	flag.Var(
		&dnsProxyHijack, "dns-proxy-hijack",
		"Register keyword triggering redirection to 127.0.0.1",
	)

	// httpProxy
	httpProxyAddress = flag.String(
		"http-proxy-address", "127.0.0.1:80",
		"Address where the HTTP proxy should listen",
	)
	flag.Var(
		&httpProxyBlock, "http-proxy-block",
		"Register keyword triggering HTTP 541 censorship",
	)
	httpProxyDNSAddress = flag.String(
		"http-proxy-dns-address", "1.1.1.1:853",
		"Address of the upstream DNS to be used by the proxy",
	)
	httpProxyDNSTransport = flag.String(
		"http-proxy-dns-transport", "dot",
		"Transport to be used with the upstream DNS",
	)

	// tlsProxy
	tlsProxyAddress = flag.String(
		"tls-proxy-address", "127.0.0.1:443",
		"Address where the HTTP proxy should listen",
	)
	flag.Var(
		&tlsProxyBlock, "tls-proxy-block",
		"Register keyword triggering TLS censorship",
	)
	tlsProxyDNSAddress = flag.String(
		"tls-proxy-dns-address", "1.1.1.1:853",
		"Address of the upstream DNS to be used by the proxy",
	)
	tlsProxyDNSTransport = flag.String(
		"tls-proxy-dns-transport", "dot",
		"Transport to be used with the upstream DNS",
	)
}

func dnsProxyStart() *dns.Server {
	proxy, err := resolver.NewCensoringResolver(
		dnsProxyBlock, dnsProxyHijack,
		*dnsProxyDNSTransport, *dnsProxyDNSAddress,
	)
	rtx.Must(err, "dns.NewCensoringResolver failed")
	server, err := proxy.Start(*dnsProxyAddress)
	rtx.Must(err, "proxy.Start failed")
	return server
}

func httpProxyStart() *http.Server {
	proxy, err := httpproxy.NewCensoringProxy(
		httpProxyBlock, *httpProxyDNSTransport, *httpProxyDNSAddress,
	)
	rtx.Must(err, "http.NewCensoringProxy failed")
	server, _, err := proxy.Start(*httpProxyAddress)
	rtx.Must(err, "proxy.Start failed")
	return server
}

func tlsProxyStart() net.Listener {
	proxy, err := tlsproxy.NewCensoringProxy(
		tlsProxyBlock, *tlsProxyDNSTransport, *tlsProxyDNSAddress,
	)
	rtx.Must(err, "tls.NewCensoringProxy failed")
	listener, err := proxy.Start(*tlsProxyAddress)
	rtx.Must(err, "proxy.Start failed")
	return listener
}

func main() {
	flag.Parse()
	dnsProxyStart()
	httpProxyStart()
	go iptables.Start()
	defer iptables.Stop()
	tlsProxyStart()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
}
