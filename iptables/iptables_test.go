package iptables

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ooni/jafar/resolver"
)

func TestUnitCannotApplyPolicy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("not implemented on this platform")
	}
	policy := NewCensoringPolicy()
	policy.DropIPs = []string{"antani"}
	if err := policy.Apply(); err == nil {
		t.Fatal("expected an error here")
	}
	defer policy.Waive()
}

func TestUnitCreateChainsError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("not implemented on this platform")
	}
	policy := NewCensoringPolicy()
	if err := policy.Apply(); err != nil {
		t.Fatal(err)
	}
	defer policy.Waive()
	// you should not be able to apply the policy when there is
	// already a policy, you need to waive it first
	if err := policy.Apply(); err == nil {
		t.Fatal("expected an error here")
	}
}

func TestIntegrationDropIP(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("not implemented on this platform")
	}
	policy := NewCensoringPolicy()
	policy.DropIPs = []string{"1.1.1.1"}
	if err := policy.Apply(); err != nil {
		t.Fatal(err)
	}
	defer policy.Waive()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "1.1.1.1:853")
	if err == nil {
		t.Fatalf("expected an error here")
	}
	if err.Error() != "dial tcp 1.1.1.1:853: i/o timeout" {
		t.Fatal("unexpected error occurred")
	}
	if conn != nil {
		t.Fatal("expected nil connection here")
	}
}

func TestIntegrationDropKeyword(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("not implemented on this platform")
	}
	policy := NewCensoringPolicy()
	policy.DropKeywords = []string{"ooni.io"}
	if err := policy.Apply(); err != nil {
		t.Fatal(err)
	}
	defer policy.Waive()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequest("GET", "http://www.ooni.io", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err == nil {
		t.Fatal("expected an error here")
	}
	if err.Error() != "Get http://www.ooni.io: context deadline exceeded" {
		t.Fatal("unexpected error occurred")
	}
	if resp != nil {
		t.Fatal("expected nil response here")
	}
}

func TestIntegrationResetIP(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("not implemented on this platform")
	}
	policy := NewCensoringPolicy()
	policy.ResetIPs = []string{"1.1.1.1"}
	if err := policy.Apply(); err != nil {
		t.Fatal(err)
	}
	defer policy.Waive()
	conn, err := (&net.Dialer{}).Dial("tcp", "1.1.1.1:853")
	if err == nil {
		t.Fatalf("expected an error here")
	}
	if err.Error() != "dial tcp 1.1.1.1:853: connect: connection refused" {
		t.Fatal("unexpected error occurred")
	}
	if conn != nil {
		t.Fatal("expected nil connection here")
	}
}

func TestIntegrationResetKeyword(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("not implemented on this platform")
	}
	policy := NewCensoringPolicy()
	policy.ResetKeywords = []string{"ooni.io"}
	if err := policy.Apply(); err != nil {
		t.Fatal(err)
	}
	defer policy.Waive()
	resp, err := http.Get("http://www.ooni.io")
	if err == nil {
		t.Fatal("expected an error here")
	}
	if strings.Contains(err.Error(), "read: connection reset by peer") == false {
		t.Fatal("unexpected error occurred")
	}
	if resp != nil {
		t.Fatal("expected nil response here")
	}
}

func TestIntegrationHijackDNS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("not implemented on this platform")
	}
	resolver, err := resolver.NewCensoringResolver(
		[]string{"ooni.io"}, nil, nil, "dot", "1.1.1.1:853",
	)
	if err != nil {
		t.Fatal(err)
	}
	server, err := resolver.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()
	policy := NewCensoringPolicy()
	policy.HijackDNSAddress = server.PacketConn.LocalAddr().String()
	if err := policy.Apply(); err != nil {
		t.Fatal(err)
	}
	defer policy.Waive()
	addrs, err := net.LookupHost("www.ooni.io")
	if err == nil {
		t.Fatal("expected an error here")
	}
	if strings.Contains(err.Error(), "no such host") == false {
		t.Fatal("unexpected error occurred")
	}
	if addrs != nil {
		t.Fatal("expected nil addrs here")
	}
}
