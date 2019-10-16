// jafar is a censorship simulator. We used to have an evilgenius doing
// that but now we're resorting to an even more evil grand viezir.
package main

import (
	"flag"
	"os"
	"os/signal"

	"github.com/ooni/jafar/connectproxy"
	"github.com/ooni/jafar/dnsproxy"
	"github.com/ooni/jafar/pktinjector"
)

func main() {
	flag.Parse()
	go connectproxy.Start()
	go dnsproxy.Start()
	go pktinjector.Start()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
}
