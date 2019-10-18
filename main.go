// jafar is a censorship simulator. We used to have an evilgenius doing
// that but now we're resorting to an even more evil grand viezir.
package main

import (
	"flag"
	"net/http"
	"os"
	"os/signal"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/ooni/jafar/httpproxy"
	"github.com/ooni/jafar/iptables"
	"github.com/ooni/jafar/resolver"
	"github.com/ooni/jafar/tlsproxy"
)

var (
	httpProxyAddress      *string
	httpProxyBlock        flagx.StringArray
	httpProxyDNSAddress   *string
	httpProxyDNSTransport *string
)

func init() {
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

func main() {
	flag.Parse()
	httpProxyStart()
	go iptables.Start()
	defer iptables.Stop()
	go resolver.Start()
	go tlsproxy.Start()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
}
