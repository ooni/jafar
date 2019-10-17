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
	blocked  flagx.StringArray
	upstream = flag.String(
		"resolver-upstream", "8.8.8.8:53",
		"Upstream DNS resolver to be used by the this resolver",
	)
)

func init() {
	flag.Var(
		&blocked, "resolver-blocked",
		"Censor with NXDOMAIN queries received by resolver containing <value>",
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
	for _, pattern := range blocked {
		if strings.Contains(name, pattern) {
			blockdomain(w, r)
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
