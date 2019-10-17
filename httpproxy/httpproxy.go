// Package httpproxy contains an HTTP transparent proxy.
package httpproxy

import (
	"flag"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/apex/log"
	"github.com/m-lab/go/rtx"
	"github.com/ooni/jafar/conf"
)

var (
	address = flag.String("httpproxy.address", "127.0.0.1:80",
		"Address where the HTTP transparent proxy should listen")
)

func handler(w http.ResponseWriter, r *http.Request) {
	// TODO(bassosimone): because this is integration testing code, I am
	// not bothering with making sure one cannot force the proxy to connect
	// to itself and enter into some kind of infinite loop.
	URL, err := url.Parse(r.RequestURI)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	for _, pattern := range conf.Patterns {
		if strings.Contains(URL.Host, pattern) {
			w.WriteHeader(http.StatusUnavailableForLegalReasons)
			return
		}
	}
	r.Header.Del("Proxy-Connection")
	resp, err := http.DefaultClient.Do(&http.Request{
		URL:    URL,
		Header: r.Header,
		Body:   r.Body,
	})
	if err != nil {
		log.WithError(err).Warn("http.DefaultClient.Do failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		w.Header()[key] = values
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Warn("ioutil.ReadAll failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(data)
}

// Start starts the HTTP transparent proxy.
func Start() {
	err := http.ListenAndServe(*address, http.HandlerFunc(handler))
	rtx.Must(err, "http.ListenAndServe failed")
}
