// Package hosts contains a parser for /etc/hosts
package hosts

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
)

// Conf is the static DNS configuration
type Conf struct {
	m map[string]net.IP
}

// MakeConf reads a new configuration from file
func MakeConf(path string) (*Conf, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	conf := new(Conf)
	reader := bufio.NewReader(bytes.NewReader(data))
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		if err == io.EOF {
			break
		}
		line = line[:len(line)-1] // "[...] and including the delimiter"
		if off := strings.Index(line, "#"); off != -1 {
			line = line[:off]
		}
		vec := strings.Split(line, " ")
		if len(vec) != 2 {
			return nil, fmt.Errorf("more than two tokens per line: %s", line)
		}
		address, domain := vec[0], vec[1]
		ipaddr := net.ParseIP(address)
		if ipaddr == nil {
			return nil, fmt.Errorf("not a valid IP: %s", address)
		}
		conf.m[domain] = ipaddr
	}
	return conf, nil
}

// Get returns the IP mapped by domain or nil.
func (c *Conf) Get(domain string) net.IP {
	ipaddr, _ := c.m[domain]
	return ipaddr
}
