// Package httpproxy contains an HTTP transparent proxy.
package httpproxy

import (
	"flag"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/apex/log"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
)

var (
	address = flag.String(
		"httpproxy-address", "127.0.0.1:80",
		"Address where the HTTP transparent proxy should listen",
	)
	blocked flagx.StringArray
)

func init() {
	flag.Var(
		&blocked, "httpproxy-blocked",
		"Censor with 451 HTTP requests via proxy if host contains <value>",
	)
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Implementation note: use Via header to detect in a loose way
	// requests originated by us and directed to us
	if r.Header.Get("Via") != "" || r.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	for _, pattern := range blocked {
		if strings.Contains(r.Host, pattern) {
			w.WriteHeader(http.StatusUnavailableForLegalReasons)
			return
		}
	}
	r.Header.Add("Via", "jafar/0.1.0")
	resp, err := http.DefaultClient.Do(&http.Request{
		Body:   r.Body,
		Header: r.Header,
		Method: r.Method,
		URL: &url.URL{
			Host:   r.Host,
			Path:   r.RequestURI,
			Scheme: "http",
		},
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
