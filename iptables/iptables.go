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
	drop  flagx.StringArray
	reset flagx.StringArray
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
}

// Stop removes iptables rules
func Stop() {
	mustExec("iptables", "--flush")
}