# Jafar

> We stepped up the game of simulating censorship upgrading from the
> evil genius to the evil grand vizier.

[![Build Status](https://travis-ci.org/ooni/jafar.svg?branch=master)](https://travis-ci.org/ooni/jafar) [![Coverage Status](https://coveralls.io/repos/github/ooni/jafar/badge.svg?branch=master)](https://coveralls.io/github/ooni/jafar?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/ooni/jafar)](https://goreportcard.com/report/github.com/ooni/jafar)

Jafar is a censorship simulation tool. Some of its functionality are more
easily coupled with github.com/ooni/netx.

## Building

We use Go >= 1.13. Jafar also needs the C library headers,
iptables installed, and root permissions.

With Linux Alpine edge, you can compile Jafar with:

```
# apk add go git musl-dev iptables
# go build -v .
```

Otherwise, using Docker:

```
docker build -t jafar-runner .
docker run -it --privileged -v`pwd`:/jafar -w/jafar jafar-runner
go build -v .
```

## Usage

You need to run Jafar as root. You can get a complete list
of all flags using `./jafar -help`. Jafar is composed of modules. Each
module is controllable via flags. We describe modules below.

### iptables

[![GoDoc](https://godoc.org/github.com/ooni/jafar/iptables?status.svg)](
https://godoc.org/github.com/ooni/jafar/iptables)

The iptables module is only available on Linux. It exports these flags:

```
  -iptables-drop-ip value
        Drop traffic to the specified IP address
  -iptables-drop-keyword value
        Drop traffic containing the specified keyword
  -iptables-hijack-dns-to string
        Hijack all DNS UDP traffic to the specified endpoint
  -iptables-reset-ip value
        Reset TCP/IP traffic to the specified IP address
  -iptables-reset-keyword value
        Reset TCP/IP traffic containing the specified keyword
```

The difference between `drop` and `reset` is that in the former case
a packet is dropped, in the latter case a RST is sent.

The difference between `ip` and `keyword` flags is that the former
match an outgoing IP, the latter uses DPI.

The `drop` and `reset` rules allow you to simulate, respectively, when
operations timeout and when a connection cannot be established (with
`reset` and `ip`) or is reset after a keyword is seen (with `keyword`).

Hijacking DNS traffic is useful, for example, to redirect all DNS UDP
traffic from the box to the `dns-proxy` module.

Note that with `-iptables-drop-keyword`, DNS queries containing such
keyword will fail returning `EPERM`. For a more realistic approach to
dropping specific DNS packets, combine DNS traffic hijacking with
`-dns-proxy-ignore`, to "drop" packets at the DNS proxy.

### dns-proxy (aka resolver)

[![GoDoc](https://godoc.org/github.com/ooni/jafar/resolver?status.svg)](
https://godoc.org/github.com/ooni/jafar/resolver)

The DNS proxy or resolver allows to manipulate DNS. Unless you use DNS
hijacking, you will need to configure your application explicitly.

```
  -dns-proxy-address string
        Address where the DNS proxy should listen (default "127.0.0.1:53")
  -dns-proxy-block value
        Register keyword triggering NXDOMAIN censorship
  -dns-proxy-dns-address string
        Address of the upstream DNS to be used by the proxy (default "1.1.1.1:853")
  -dns-proxy-dns-transport string
        Transport to be used with the upstream DNS (default "dot")
  -dns-proxy-hijack value
        Register keyword triggering redirection to 127.0.0.1
  -dns-proxy-ignore value
        Register keyword causing the proxy to ignore the query
```

The `-dns-proxy-address` flag controls the endpoint where the proxy is
listening. The `-dns-proxy-dns-{address,transport}` flags allow to choose
a different upstream DNS with transports like `dot` and `doh`. Remember
to avoid using the `udp` transport if you're also using DNS hijacking since
these two settings will probably clash. See github.com/ooni/netx and in
particular the documentation of ConfigureDNS for more information concerning
the different transports that you can use.

The `-dns-proxy-block` tells the resolver that every incoming request whose
query contains the specifed string shall receive an `NXDOMAIN` reply.

The `-dns-proxy-hijack` is similar but instead lies and returns to the
client that the requested domain is at `127.0.0.1`. This is an opportunity
to redirect traffic to the HTTP and TLS proxies.

The `-dns-proxy-ignore` is similar but instead just ignores the query.

### http-proxy

[![GoDoc](https://godoc.org/github.com/ooni/jafar/httpproxy?status.svg)](
https://godoc.org/github.com/ooni/jafar/httpproxy)

The HTTP proxy is an HTTP proxy that may refuse to forward some
specific requests. It's controlled by these flags:

```
  -http-proxy-address string
        Address where the HTTP proxy should listen (default "127.0.0.1:80")
  -http-proxy-block value
        Register keyword triggering HTTP 451 censorship
  -http-proxy-dns-address string
        Address of the upstream DNS to be used by the proxy (default "1.1.1.1:853")
  -http-proxy-dns-transport string
        Transport to be used with the upstream DNS (default "dot")
```

The `-http-proxy-address` and `-http-proxy-dns-{address,transport}` flags
have the same semantics they have for the DNS proxy, and they also have the
same caveats regarding mixing DNS hijacking and `udp` transports.

The `-http-proxy-block` flag tells the proxy that it should return a `451`
response for every request whose `Host` contains the specified string.

### tls-proxy

[![GoDoc](https://godoc.org/github.com/ooni/jafar/tlsproxy?status.svg)](
https://godoc.org/github.com/ooni/jafar/tlsproxy)

TLS proxy is a proxy that routes traffic to specific servers depending
on their SNI value. It is controlled by the following flags:

```
  -tls-proxy-address string
        Address where the HTTP proxy should listen (default "127.0.0.1:443")
  -tls-proxy-block value
        Register keyword triggering TLS censorship
  -tls-proxy-dns-address string
        Address of the upstream DNS to be used by the proxy (default "1.1.1.1:853")
  -tls-proxy-dns-transport string
        Transport to be used with the upstream DNS (default "dot")
```

The `-tls-proxy-address` and `-tls-proxy-dns-{address,transport}` flags
have the same semantics they have for the DNS proxy, and they also have the
same caveats regarding mixing DNS hijacking and `udp` transports.

The `-tls-proxy-block` specifies which string or strings should cause the
proxy to return an internal-erorr alert when the incoming ClientHello's SNI
contains one of the strings provided with this option.

## Examples

Block `play.google.com` with RST injection, force DNS traffic to use the our
DNS proxy, and force it to censor `play.google.com` with `NXDOMAIN`.

```
# ./jafar -iptables-reset-keyword play.google.com \
          -iptables-hijack-dns-to 127.0.0.1:5353  \
          -dns-proxy-address 127.0.0.1:5353       \
          -dns-proxy-block play.google.com
```

Force all traffic through the HTTP and TLS proxy and use them to censor
`play.google.com` using HTTP 451 and responding with TLS alerts:

```
# ./jafar -iptables-hijack-dns-to 127.0.0.1:5353 \
          -dns-proxy-address 127.0.0.1:5353      \
          -dns-proxy-hijack play.google.com      \
          -http-proxy-block play.google.com      \
          -tls-proxy-block play.google.com
```
