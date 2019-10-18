package main

import "testing"

func TestLame(t *testing.T) {
	*dnsProxyAddress = "127.0.0.1:0"
	*httpProxyAddress = "127.0.0.1:0"
	*tlsProxyAddress = "127.0.0.1:0"
	close(mainCh)
	main()
}
