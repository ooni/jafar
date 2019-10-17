// Package dnsproxy contains the DNS proxy
package dnsproxy

import (
	"flag"
	"net"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/m-lab/go/rtx"
	"github.com/miekg/dns"
	"github.com/ooni/jafar/conf"
)

var (
	address = flag.String("dnsproxy.address", "127.0.0.1:53",
		"Address where the DNS proxy should listen")
	upstreamDNS = flag.String("dnsproxy.upstream", "8.8.8.8:53",
		"Upstream DNS server to use to resolve noncensored input")
)

func roundtrip(w dns.ResponseWriter, r *dns.Msg) error {
	conn, err := net.Dial("udp", *upstreamDNS)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	data, err := r.Pack()
	if err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	data = make([]byte, 4096)
	count, err := conn.Read(data)
	if err != nil {
		return err
	}
	m := new(dns.Msg)
	if err = m.Unpack(data[:count]); err != nil {
		return err
	}
	w.WriteMsg(m)
	return nil
}

func blockdomain(w dns.ResponseWriter, r *dns.Msg) {
	log.Infof("blockdomain: %s", r.Question[0].Name)
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeNameError)
	m.Compress = true
	m.MsgHdr.RecursionAvailable = true
	w.WriteMsg(m)
}

func handle(w dns.ResponseWriter, r *dns.Msg) {
	name := r.Question[0].Name
	for _, s := range conf.Patterns {
		if strings.Contains(name, s) {
			blockdomain(w, r)
			return
		}
	}
	log.Debugf("defaultdns: %s", name)
	if err := roundtrip(w, r); err != nil {
		m := new(dns.Msg)
		m.Compress = true
		m.MsgHdr.RecursionAvailable = true
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
	}
}

// Start starts the DNS proxy
func Start() {
	dns.HandleFunc(".", handle)
	server := &dns.Server{Addr: *address, Net: "udp"}
	err := server.ListenAndServe()
	rtx.Must(err, "dnsListenAndServe failed")
}
