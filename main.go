// jafar is the grand vizier of censorship simulation.
package main

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/miekg/dns"
	"github.com/ooni/jafar/badproxy"
	"github.com/ooni/jafar/httpproxy"
	"github.com/ooni/jafar/iptables"
	"github.com/ooni/jafar/resolver"
	"github.com/ooni/jafar/shellx"
	"github.com/ooni/jafar/tlsproxy"
)

var (
	badProxyAddress     *string
	badProxyAddressTLS  *string
	badProxyTLSOutputCA *string

	dnsProxyAddress      *string
	dnsProxyBlock        flagx.StringArray
	dnsProxyDNSAddress   *string
	dnsProxyDNSTransport *string
	dnsProxyHijack       flagx.StringArray
	dnsProxyIgnore       flagx.StringArray

	httpProxyAddress      *string
	httpProxyBlock        flagx.StringArray
	httpProxyDNSAddress   *string
	httpProxyDNSTransport *string

	iptablesDropIP          flagx.StringArray
	iptablesDropKeywordHex  flagx.StringArray
	iptablesDropKeyword     flagx.StringArray
	iptablesHijackDNSTo     *string
	iptablesHijackHTTPSTo   *string
	iptablesHijackHTTPTo    *string
	iptablesResetIP         flagx.StringArray
	iptablesResetKeywordHex flagx.StringArray
	iptablesResetKeyword    flagx.StringArray

	mainCh      chan os.Signal
	mainCommand *string
	mainUser    *string

	tlsProxyAddress      *string
	tlsProxyBlock        flagx.StringArray
	tlsProxyDNSAddress   *string
	tlsProxyDNSTransport *string
)

func init() {
	// badProxy
	badProxyAddress = flag.String(
		"bad-proxy-address", "127.0.0.1:7117",
		"Address where to listen for TCP connections",
	)
	badProxyAddressTLS = flag.String(
		"bad-proxy-address-tls", "127.0.0.1:4114",
		"Address where to listen for TLS connections",
	)
	badProxyTLSOutputCA = flag.String(
		"bad-proxy-tls-output-ca", "badproxy.pem",
		"File where to write the CA used by the bad proxy",
	)

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
	flag.Var(
		&dnsProxyIgnore, "dns-proxy-ignore",
		"Register keyword causing the proxy to ignore the query",
	)

	// httpProxy
	httpProxyAddress = flag.String(
		"http-proxy-address", "127.0.0.1:80",
		"Address where the HTTP proxy should listen",
	)
	flag.Var(
		&httpProxyBlock, "http-proxy-block",
		"Register keyword triggering HTTP 451 censorship",
	)
	httpProxyDNSAddress = flag.String(
		"http-proxy-dns-address", "1.1.1.1:853",
		"Address of the upstream DNS to be used by the proxy",
	)
	httpProxyDNSTransport = flag.String(
		"http-proxy-dns-transport", "dot",
		"Transport to be used with the upstream DNS",
	)

	// iptables
	flag.Var(
		&iptablesDropIP, "iptables-drop-ip",
		"Drop traffic to the specified IP address",
	)
	flag.Var(
		&iptablesDropKeywordHex, "iptables-drop-keyword-hex",
		"Drop traffic containing the specified keyword in hex",
	)
	flag.Var(
		&iptablesDropKeyword, "iptables-drop-keyword",
		"Drop traffic containing the specified keyword",
	)
	iptablesHijackDNSTo = flag.String(
		"iptables-hijack-dns-to", "",
		"Hijack all DNS UDP traffic to the specified endpoint",
	)
	iptablesHijackHTTPSTo = flag.String(
		"iptables-hijack-https-to", "",
		"Hijack all HTTPS traffic to the specified endpoint",
	)
	iptablesHijackHTTPTo = flag.String(
		"iptables-hijack-http-to", "",
		"Hijack all HTTP traffic to the specified endpoint",
	)
	flag.Var(
		&iptablesResetIP, "iptables-reset-ip",
		"Reset TCP/IP traffic to the specified IP address",
	)
	flag.Var(
		&iptablesResetKeywordHex, "iptables-reset-keyword-hex",
		"Reset TCP/IP traffic containing the specified keyword in hex",
	)
	flag.Var(
		&iptablesResetKeyword, "iptables-reset-keyword",
		"Reset TCP/IP traffic containing the specified keyword",
	)

	// main
	mainCh = make(chan os.Signal, 1)
	signal.Notify(
		mainCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT,
	)
	mainCommand = flag.String("main-command", "", "Optional command to execute")
	mainUser = flag.String("main-user", "nobody", "Run command as user")

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

func badProxyStart() net.Listener {
	proxy := badproxy.NewCensoringProxy()
	listener, err := proxy.Start(*badProxyAddress)
	rtx.Must(err, "proxy.Start failed")
	return listener
}

func badProxyStartTLS() net.Listener {
	proxy := badproxy.NewCensoringProxy()
	listener, cert, err := proxy.StartTLS(*badProxyAddressTLS)
	rtx.Must(err, "proxy.Start failed")
	err = ioutil.WriteFile(*badProxyTLSOutputCA, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}), 0644)
	rtx.Must(err, "ioutil.WriteFile failed")
	return listener
}

func dnsProxyStart() *dns.Server {
	proxy, err := resolver.NewCensoringResolver(
		dnsProxyBlock, dnsProxyHijack, dnsProxyIgnore,
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

func iptablesStart() *iptables.CensoringPolicy {
	policy := iptables.NewCensoringPolicy()
	// For robustness waive the policy so we start afresh
	policy.Waive()
	policy.DropIPs = iptablesDropIP
	policy.DropKeywordsHex = iptablesDropKeywordHex
	policy.DropKeywords = iptablesDropKeyword
	policy.HijackDNSAddress = *iptablesHijackDNSTo
	policy.HijackHTTPSAddress = *iptablesHijackHTTPSTo
	policy.HijackHTTPAddress = *iptablesHijackHTTPTo
	policy.ResetIPs = iptablesResetIP
	policy.ResetKeywordsHex = iptablesResetKeywordHex
	policy.ResetKeywords = iptablesResetKeyword
	err := policy.Apply()
	rtx.Must(err, "policy.Apply failed")
	return policy
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

func mustx(err error, message string, osExit func(int)) {
	if err != nil {
		var (
			exitcode = 1
			exiterr  *exec.ExitError
		)
		if errors.As(err, &exiterr) {
			exitcode = exiterr.ExitCode()
		}
		log.Errorf("%s", message)
		osExit(exitcode)
	}
}

func main() {
	flag.Parse()
	log.SetLevel(log.DebugLevel)
	log.SetHandler(cli.Default)
	badlistener := badProxyStart()
	defer badlistener.Close()
	badtlslistener := badProxyStartTLS()
	defer badtlslistener.Close()
	dnsproxy := dnsProxyStart()
	defer dnsproxy.Shutdown()
	httpproxy := httpProxyStart()
	defer httpproxy.Close()
	tlslistener := tlsProxyStart()
	defer tlslistener.Close()
	policy := iptablesStart()
	var err error
	if *mainCommand != "" {
		err = shellx.RunCommandline(fmt.Sprintf(
			"sudo -u '%s' -- %s", *mainUser, *mainCommand,
		))
	} else {
		<-mainCh
	}
	policy.Waive()
	mustx(err, "subcommand failed", os.Exit)
}
