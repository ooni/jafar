package main

import (
	"errors"
	"os"
	"testing"

	"github.com/ooni/jafar/shellx"
)

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

func TestMustx(t *testing.T) {
	t.Run("with no error", func(t *testing.T) {
		var called int
		mustx(nil, "", func(int) {
			called++
		})
		if called != 0 {
			t.Fatal("should not happen")
		}
	})
	t.Run("with non-exit-code error", func(t *testing.T) {
		var (
			called   int
			exitcode int
		)
		mustx(errors.New("antani"), "", func(ec int) {
			called++
			exitcode = ec
		})
		if called != 1 {
			t.Fatal("not called?!")
		}
		if exitcode != 1 {
			t.Fatal("unexpected exitcode value")
		}
	})
	t.Run("with exit-code error", func(t *testing.T) {
		var (
			called   int
			exitcode int
		)
		err := shellx.Run("curl", "-sf", "") // cause exitcode == 3
		mustx(err, "", func(ec int) {
			called++
			exitcode = ec
		})
		if called != 1 {
			t.Fatal("not called?!")
		}
		if exitcode != 3 {
			t.Fatal("unexpected exitcode value")
		}
	})
}
