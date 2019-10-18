package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

func TestNewCensoringResolverFailure(t *testing.T) {
	resolver, err := NewCensoringResolver(
		[]string{""}, []string{""}, "antani", "1.1.1.1:853",
	)
	if err == nil {
		t.Fatal("expected an error here")
	}
	if resolver != nil {
		t.Fatal("expected nil resolver here")
	}
}

func TestIntegrationPass(t *testing.T) {
	server := newresolver(t, "ooni.io", "ooni.nu")
	checkrequest(t, server, "example.com", "success")
	killserver(t, server)
}

func TestIntegrationBlock(t *testing.T) {
	server := newresolver(t, "ooni.io", "ooni.nu")
	checkrequest(t, server, "mia-ps.ooni.io", "blocked")
	killserver(t, server)
}

func TestIntegrationRedirect(t *testing.T) {
	server := newresolver(t, "ooni.io", "ooni.nu")
	checkrequest(t, server, "hkgmetadb.ooni.nu", "hijacked")
	killserver(t, server)
}

func TestIntegrationLookupFailure(t *testing.T) {
	server := newresolver(t, "", "")
	// we should receive same response as when we're blocked
	checkrequest(t, server, "example.antani", "blocked")
	killserver(t, server)
}

func TestFailureNoQuestion(t *testing.T) {
	resolver, err := NewCensoringResolver(
		[]string{""}, []string{""}, "dot", "1.1.1.1:853",
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver.ServeDNS(&fakeResponseWriter{t: t}, new(dns.Msg))
}

func TestListenFailure(t *testing.T) {
	resolver, err := NewCensoringResolver(
		[]string{""}, []string{""}, "dot", "1.1.1.1:853",
	)
	if err != nil {
		t.Fatal(err)
	}
	server, err := resolver.Start("8.8.8.8:53")
	if err == nil {
		t.Fatal("expected an error here")
	}
	if server != nil {
		t.Fatal("expected nil server here")
	}
}

func newresolver(t *testing.T, blocked, hijacked string) *dns.Server {
	resolver, err := NewCensoringResolver(
		[]string{blocked}, []string{hijacked},
		// using faster dns because dot here causes miekg/dns's
		// dns.Exchange to timeout and I don't want more complexity
		"system", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	server, err := resolver.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func killserver(t *testing.T, server *dns.Server) {
	err := server.Shutdown()
	if err != nil {
		t.Fatal(err)
	}
}

func checkrequest(
	t *testing.T, server *dns.Server, host string, expectStatus string,
) {
	address := server.PacketConn.LocalAddr().String()
	query := newquery(host)
	reply, err := dns.Exchange(query, address)
	if err != nil {
		t.Fatal(err)
	}
	switch expectStatus {
	case "success":
		checksuccess(t, reply)
	case "hijacked":
		checkhijacked(t, reply)
	case "blocked":
		checkblocked(t, reply)
	default:
		panic("unexpected value")
	}
}

func checksuccess(t *testing.T, reply *dns.Msg) {
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatal("unexpected rcode")
	}
	if len(reply.Answer) < 1 {
		t.Fatal("too few answers")
	}
	for _, answer := range reply.Answer {
		if rr, ok := answer.(*dns.A); ok {
			if rr.A.String() == "127.0.0.1" {
				t.Fatal("unexpected hijacked response here")
			}
		}
	}
}

func checkhijacked(t *testing.T, reply *dns.Msg) {
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatal("unexpected rcode")
	}
	if len(reply.Answer) < 1 {
		t.Fatal("too few answers")
	}
	for _, answer := range reply.Answer {
		if rr, ok := answer.(*dns.A); ok {
			if rr.A.String() != "127.0.0.1" {
				t.Fatal("unexpected non-hijacked response here")
			}
		}
	}
}

func checkblocked(t *testing.T, reply *dns.Msg) {
	if reply.Rcode != dns.RcodeNameError {
		t.Fatal("unexpected rcode")
	}
	if len(reply.Answer) >= 1 {
		t.Fatal("too many answers")
	}
}

func newquery(name string) *dns.Msg {
	query := new(dns.Msg)
	query.Id = dns.Id()
	query.RecursionDesired = true
	query.Question = append(query.Question, dns.Question{
		Name:   dns.Fqdn(name),
		Qclass: dns.ClassINET,
		Qtype:  dns.TypeA,
	})
	return query
}

type fakeResponseWriter struct {
	dns.ResponseWriter
	t *testing.T
}

func (rw *fakeResponseWriter) WriteMsg(m *dns.Msg) error {
	if m.Rcode != dns.RcodeServerFailure {
		rw.t.Fatal("unexpected rcode")
	}
	return nil
}
