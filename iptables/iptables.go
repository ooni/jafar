// Package iptables contains code for managing iptables rules
package iptables

import (
	"flag"
	"net"
	"os"
	"os/exec"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
)

var (
	drop       flagx.StringArray
	reset      flagx.StringArray
	routeDNSTo = flag.String(
		"iptables-route-dns-to", "127.0.0.1:53",
		"Route all DNS traffic to a specific address",
	)
)

func init() {
	flag.Var(
		&drop, "iptables-drop",
		"Drop TCP stream segments containing <value>",
	)
	flag.Var(
		&reset, "iptables-rst",
		"Reset TCP stream if it contains <value>",
	)
}

func mustExec(name string, arg ...string) {
	cmd := exec.Command(name, arg...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	rtx.Must(err, "command failed")
}

// Start installs iptables rules
func Start() {
	for _, pattern := range drop {
		if net.ParseIP(pattern) != nil {
			mustExec(
				"iptables", "-A", "OUTPUT", "-d", pattern, "-j", "DROP",
			)
		} else {
			mustExec(
				"iptables", "-A", "OUTPUT", "-m", "string", "--algo", "bm",
				"--string", pattern, "-j", "DROP",
			)
		}
	}
	for _, pattern := range reset {
		if net.ParseIP(pattern) != nil {
			mustExec(
				"iptables", "-A", "OUTPUT", "--proto", "tcp", "-d", pattern,
				"-j", "REJECT", "--reject-with", "tcp-reset",
			)
		} else {
			mustExec(
				"iptables", "-A", "OUTPUT", "-m", "string", "--proto", "tcp", "--algo",
				"bm", "--string", pattern, "-j", "REJECT", "--reject-with", "tcp-reset",
			)
		}
	}
	if *routeDNSTo != "" {
		// Hijack any DNS query, like the Vodafone station does when using the
		// secure network feature. Our transparent proxies will use DoT, in order
		// to bypass this restriction and avoid routing loop.
		mustExec(
			"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp",
			"--dport", "53", "-j", "DNAT", "--to", *routeDNSTo,
		)
	}
}

// Stop removes iptables rules
func Stop() {
	mustExec("iptables", "--flush")
	mustExec("iptables", "--flush", "--table", "nat")
}
