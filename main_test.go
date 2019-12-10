package main

import "testing"

import "os"

func TestIntegrationNoCommand(t *testing.T) {
	*dnsProxyAddress = "127.0.0.1:0"
	*httpProxyAddress = "127.0.0.1:0"
	*tlsProxyAddress = "127.0.0.1:0"
	go func() {
		mainCh <- os.Interrupt
	}()
	main()
}

func TestIntegrationWithCommand(t *testing.T) {
	*dnsProxyAddress = "127.0.0.1:0"
	*httpProxyAddress = "127.0.0.1:0"
	*tlsProxyAddress = "127.0.0.1:0"
	*mainCommand = "whoami"
	defer func() {
		*mainCommand = ""
	}()
	main()
}
