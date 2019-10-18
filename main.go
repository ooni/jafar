// jafar is a censorship simulator. We used to have an evilgenius doing
// that but now we're resorting to an even more evil grand viezir.
package main

import (
	"flag"
	"os"
	"os/signal"

	"github.com/ooni/jafar/httpproxy"
	"github.com/ooni/jafar/iptables"
	"github.com/ooni/jafar/resolver"
	"github.com/ooni/jafar/tlsproxy"
)

func main() {
	flag.Parse()
	go httpproxy.Start()
	go iptables.Start()
	defer iptables.Stop()
	go resolver.Start()
	go tlsproxy.Start()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
}
