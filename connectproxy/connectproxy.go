// Package connectproxy contains the CONNECT proxy
package connectproxy

import (
	"errors"
	"flag"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
)

var keywords flagx.StringArray

func init() {
	flag.Var(
		&keywords, "connectproxy.reset-if-match",
		"RST flow if <value> found at beginning of stream",
	)
}

func hijack(w http.ResponseWriter) (net.Conn, error) {
	conn, buffered, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return nil, err
	}
	if buffered.Reader.Buffered() > 0 {
		return nil, errors.New("unexpected buffered data")
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func splice(wg *sync.WaitGroup, left, right net.Conn, banned bool) {
	var checkbanned bool
	data := make([]byte, 1<<18)
	for {
		n, err := left.Read(data)
		if err != nil {
			break
		}
		if !checkbanned && banned {
			checkbanned = true
			s := string(data[:n])
			for _, keyword := range keywords {
				if strings.Contains(s, keyword) {
					log.Infof("connectproxy: %s", keyword)
					if tc, ok := left.(*net.TCPConn); ok {
						tc.SetLinger(0)
					}
					left.Close()
					right.Close()
					return
				}
			}
		}
		_, err = right.Write(data[:n])
		if err != nil {
			break
		}
	}
	wg.Done()
}

func connector(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT" {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	log.Infof("connect: %s", r.RequestURI)
	clientconn, err := hijack(w)
	if err != nil {
		return // internal error where doing nothing is the answer
	}
	defer clientconn.Close()
	serverconn, err := net.Dial("tcp", r.RequestURI)
	if err != nil {
		clientconn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer serverconn.Close()
	if _, err = clientconn.Write([]byte("HTTP/1.1 200 Ok\r\n\r\n")); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go splice(&wg, clientconn, serverconn, true)
	go splice(&wg, serverconn, clientconn, false)
	wg.Wait()
}

// Start starts the CONNECT proxy
func Start() {
	http.HandleFunc("/", connector)
	err := http.ListenAndServe(":8080", http.HandlerFunc(connector))
	rtx.Must(err, "http.ListenAndServe failed")
}
