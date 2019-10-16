// Package dnsproxy contains the DNS proxy
package dnsproxy

import (
	"flag"
	"net"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/miekg/dns"
)

var (
	blocked     flagx.StringArray
	redirected  flagx.StringArray
	upstreamDNS = flag.String("dnsproxy.upstream-server", "8.8.8.8:53",
		"Upstream DNS server to use to resolve noncensored input")
)

func init() {
	flag.Var(
		&blocked, "dnsproxy.nxdomain-if-match",
		"Send NXDOMAIN if query name matches <value>",
	)
	flag.Var(&redirected, "dnsproxy.redirect-if-match",
		"Redirect to 127.0.0.1 if query name matches <value>")
}

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

func redirectdomain(w dns.ResponseWriter, r *dns.Msg) {
	log.Infof("redirectdomain: %s", r.Question[0].Name)
	m := new(dns.Msg)
	m.Compress = true
	m.MsgHdr.RecursionAvailable = true
	m.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeA:
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: net.IPv4(127, 0, 0, 1),
		})
	}
	w.WriteMsg(m)
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
	for _, s := range blocked {
		if strings.Contains(name, s) {
			blockdomain(w, r)
			return
		}
	}
	for _, s := range redirected {
		if strings.Contains(name, s) {
			redirectdomain(w, r)
			return
		}
	}
	log.Infof("defaultdns: %s", name)
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
	server := &dns.Server{Addr: ":53", Net: "udp"}
	err := server.ListenAndServe()
	rtx.Must(err, "dnsListenAndServe failed")
}
