// Package resolver contains the DNS proxy
package resolver

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
	address = flag.String(
		"resolver-address", "127.0.0.1:53",
		"Address where this stub DNS resolver should listen",
	)
	blackholed flagx.StringArray
	blocked    flagx.StringArray
	hijacked   flagx.StringArray
	upstream   = flag.String(
		"resolver-upstream", "8.8.8.8:53",
		"Upstream DNS resolver to be used by the this resolver",
	)
)

func init() {
	flag.Var(
		&blackholed, "resolver-blackhole",
		"Return 127.0.0.2 for queries received by resolver containing <value>",
	)
	flag.Var(
		&blocked, "resolver-block",
		"Censor with NXDOMAIN queries received by resolver containing <value>",
	)
	flag.Var(
		&hijacked, "resolver-hijack",
		"Return 127.0.0.1 for queries received by resolver containing <value>",
	)
}

func roundtrip(w dns.ResponseWriter, r *dns.Msg) error {
	conn, err := net.Dial("udp", *upstream)
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

func meddletrip(w dns.ResponseWriter, r *dns.Msg, redirectTo net.IP) {
	log.Infof("meddletrip: %s %+v", r.Question[0].Name, redirectTo)
	m := new(dns.Msg)
	m.Compress = true
	m.MsgHdr.RecursionAvailable = true
	m.SetReply(r)
	if redirectTo != nil {
		switch r.Question[0].Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				A: redirectTo,
			})
		}
	} else {
		m.SetRcode(r, dns.RcodeNameError)
	}
	w.WriteMsg(m)
}

func handle(w dns.ResponseWriter, r *dns.Msg) {
	name := r.Question[0].Name
	for _, pattern := range blackholed {
		if strings.Contains(name, pattern) {
			meddletrip(w, r, net.IPv4(127, 0, 0, 2))
			return
		}
	}
	for _, pattern := range blocked {
		if strings.Contains(name, pattern) {
			meddletrip(w, r, nil)
			return
		}
	}
	for _, pattern := range hijacked {
		if strings.Contains(name, pattern) {
			meddletrip(w, r, net.IPv4(127, 0, 0, 1))
			return
		}
	}
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
