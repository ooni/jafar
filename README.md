# Jafar

> We stepped up the game of simulating censorship upgrading from the
> evil genius to the evil grand vizier.

Jafar is a censorship simulation tool. Some of its functionality are more
easily coupled with github.com/ooni/netx.

We use Go >= 1.11. With:

```
go build -v .
```

you compile Jafar. You need to run Jafar as root. Get brief help with
`./jafar -help`, or read on for more details.

## pktinjector

The `-censor <string>` flag turns on censorship as follows:

1. any DNS query containing `<string>` will receive an injected response
for IN, A with a RR pointing to `127.0.0.1`;

2. any TCP packet containing `<string>` will elicit an injected RST segment.

You can specfiy `-censor` more than once.

By default, we listen on all interfaces where there is a configured IPv4
address different from `127.0.0.1`. Use `-interface <name>` to listen on a
specific interface. You can specify `-interface` more than once.

## dnsproxy

The `dnsproxy` module is a DNS recursive resolver that you can configure
to return NXDOMAIN, or to return `127.0.0.1` when specific keywords
match the DNS query name. To use this functionality, you need to tell
the tool to use this module as its DNS (by default on `127.0.0.1:53/udp`).

```
-dnsproxy.nxdomain-if-match <pattern>
-dnsproxy.redirect-if-match <pattern>
-dnsproxy.upstream-server   <address>
```

The first flag can be specified multiple times. It installs a filter for which,
whenever the domain matches, we return a NXDOMAIN response.

The second flag is like the first, but we return a 127.0.0.1, IN, A, reply.

The third flag tells this code what server to use as upstream resolver. All the
queries that don't match are forwarded to such resolver.

## connectproxy

The `connectproxy` is an HTTP CONNECT proxy. If it encounters specific
keyword inside a TCP stream it is forwarding, it will sever the connection
possibly using RST. By default it listens on `127.0.0.1:8080`.

1. corporate proxy: in this scenario, you configure the proxy using the
`HTTP_PROXY` environment variable. In this scenario, well written clients
will also delegate domain resolution to the proxy.

2. meddlebox: this is similar to the previous scenario, except that your
client performs its own DNS resolutions. We are adding to `netx` code for
supporting the `OONI_NETX_PROXY` environment variable, which is supposed
to use said proxy only for performing TCP connections to addresses that it
has already resolved using another resolver.

```
-connectproxy.reset-if-match <pattern>
```

The first flag may be specified more than once. It will install patterns that,
if present on the bytes read on either direction, cause a RST.
