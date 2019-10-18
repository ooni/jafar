// +build linux

package iptables

type linuxShell struct{}

func (s *linuxShell) dropIfDestinationEquals(ip string) error {
	return runCommand("iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP")
}

func (s *linuxShell) rstIfDestinationEqualsAndIsTCP(ip string) error {
	return runCommand(
		"iptables", "-A", "OUTPUT", "--proto", "tcp", "-d", ip,
		"-j", "REJECT", "--reject-with", "tcp-reset",
	)
}

func (s *linuxShell) dropIfContainsKeyword(keyword string) error {
	return runCommand(
		"iptables", "-A", "OUTPUT", "-m", "string", "--algo", "bm",
		"--string", keyword, "-j", "DROP",
	)
}

func (s *linuxShell) rstIfContainsKeywordAndIsTCP(keyword string) error {
	return runCommand(
		"iptables", "-A", "OUTPUT", "-m", "string", "--proto", "tcp", "--algo",
		"bm", "--string", keyword, "-j", "REJECT", "--reject-with", "tcp-reset",
	)
}

func (s *linuxShell) hijackDNS(address string) error {
	// Hijack any DNS query, like the Vodafone station does when using the
	// secure network feature. Our transparent proxies will use DoT, in order
	// to bypass this restriction and avoid routing loop.
	return runCommand(
		"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp",
		"--dport", "53", "-j", "DNAT", "--to", address,
	)
}

func (s *linuxShell) waive() error {
	runCommand("iptables", "--flush", "--table", "nat")
	runCommand("iptables", "--flush")
	return nil
}

func newShell() *linuxShell {
	return &linuxShell{}
}
