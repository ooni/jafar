// Package httpproxy contains an HTTP transparent proxy.
package httpproxy

import (
	"flag"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/rtx"
	"github.com/ooni/netx/handlers"
	"github.com/ooni/netx/httpx"
)

var (
	address = flag.String(
		"httpproxy-address", "127.0.0.1:80",
		"Address where the HTTP transparent proxy should listen",
	)
	blocked flagx.StringArray
	client  *httpx.Client
)

func init() {
	flag.Var(
		&blocked, "httpproxy-block",
		"Censor with 451 HTTP requests via proxy if host contains <value>",
	)
	client = httpx.NewClient(handlers.StdoutHandler) // for debugging
	client.ConfigureDNS("dot", "1.1.1.1:853")        // hopefully non censored
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
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Host:   r.Host,
		Scheme: "http",
	})
	proxy.Transport = client.Transport
	proxy.ServeHTTP(w, r)
}

// Start starts the HTTP transparent proxy.
func Start() {
	err := http.ListenAndServe(*address, http.HandlerFunc(handler))
	rtx.Must(err, "http.ListenAndServe failed")
}
