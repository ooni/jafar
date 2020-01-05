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

### main

The main module starts all the other modules. If you don't provide the
`-main-command <command>` flag, the code will run until interrupted. If
instead you use the `-main-command` flag, you can specify a command to
run inside the censored environment. In such case, the main module
will exit when the specified command terminates. Note that the main
module will propagate the child exit code, if the child fails.

The command can also include arguments. Make sure you quote the arguments
such that your shell passes the whole string to the specified option, as
in `-main-command 'ls -lha'`. This will execute the `ls -lha` command line
inside the censored Jafar context. You can also combine that with quoting
and variables interpolation, e.g., `-main-command "echo '$USER is the
walrus'"`. The `$USER` variable will be expanded by your shell. Assuming
your user name is `paul`, then Jafar will lex the main command as `echo
"paul is the walrus"` and will execute it.

Use the `-main-user <username>` flag to select the user to use for
running child commands. By default, we use the `nobody` user for this
purpose. We implement this feature using `sudo`, therefore you need
to make sure that `sudo` is installed.

### iptables

[![GoDoc](https://godoc.org/github.com/ooni/jafar/iptables?status.svg)](
https://godoc.org/github.com/ooni/jafar/iptables)

The iptables module is only available on Linux. It exports these flags:

```
  -iptables-drop-ip value
        Drop traffic to the specified IP address
  -iptables-drop-keyword-hex value
        Drop traffic containing the specified hex keyword
  -iptables-drop-keyword value
        Drop traffic containing the specified keyword
  -iptables-hijack-dns-to string
        Hijack all DNS UDP traffic to the specified endpoint
  -iptables-hijack-https-to string
        Hijack all HTTPS traffic to the specified endpoint
  -iptables-hijack-http-to string
        Hijack all HTTP traffic to the specified endpoint
  -iptables-reset-ip value
        Reset TCP/IP traffic to the specified IP address
  -iptables-reset-keyword-hex value
        Reset TCP/IP traffic containing the specified hex keyword
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

Hijacking HTTP and HTTPS traffic actually hijacks based on ports rather
than on DPI. As a known bug, when hijacking HTTP or HTTPS traffic, we
do not hijack traffic owned by root. This is because Jafar runs as root
and therefore its traffic must not match the hijack rule.

When matching keywords, the simplest option is to use ASCII strings as
in `-iptables-drop-keyword ooni`. However, you can also specify a sequence
of hex bytes, as in `-iptables-drop-keyword-hex |6f 6f 6e 69|`.

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

### bad-proxy

```
  -bad-proxy-address string
        Address where to listen for TCP connections (default "127.0.0.1:7117")
  -bad-proxy-address-tls string
        Address where to listen for TLS connections (default "127.0.0.1:4114")
  -bad-proxy-tls-output-ca string
        File where to write the CA used by the bad proxy (default "badproxy.pem")
```

The bad proxy is a proxy that reads some bytes from any incoming connection
and then closes the connection without replying anything. This simulates a
proxy that is not working properly, hence the name of the module.

When connecting using TLS, the above behaviour happens after the handshake.

We write the CA on the file specified using `-bad-proxy-tls-output-ca` such that
tools like curl(1) can use such CA to avoid TLS handshake errors. The code will
generate on the fly a certificate for the provided SNI. Not providing any SNI in
the client Hello message will cause the TLS handshake to fail.

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

Run `ping` in a censored environment:

```
# ./jafar -iptables-drop-ip 8.8.8.8 -main-command 'ping -c3 8.8.8.8'
```

Run `curl` in a censored environment where it cannot connect to
`play.google.com` using `https`:

```
# ./jafar -iptables-hijack-https-to 127.0.0.1:443         \
          -tls-proxy-block play.google.com                \
          -main-command 'curl -Lv http://play.google.com'
```

For more usage examples, see `./test/all.bash`.

## Quality assurance of OONI implementations

The [qa](qa) directory contains scripts that can be useful to perform
quality assurance of existing OONI implementations.
