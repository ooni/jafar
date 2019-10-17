# Jafar

> We stepped up the game of simulating censorship upgrading from the
> evil genius to the evil grand vizier.

Jafar is a censorship simulation tool. Some of its functionality are more
easily coupled with github.com/ooni/netx.

We use Go >= 1.11. With:

```
go build -v .
```

you compile Jafar. Then try `./jafar` to get help. Runs as root.

## pktinjector

The `pktinjector` module will listen on a specific interface and inject
NXDOMAIN DNS responses or TCP RST segments when it encounters specific
keywords. This mechanism is not deterministic, but does not require you
to modify in any way the censorship measurement tool you're testing.

```
-pktinjector.network-interface <interfaceName>
-pktinjector.nxdomain-if-match <pattern>
-pktinjector.redirect-if-match <pattern>
-pktinjector.reset-if-match    <pattern>
```

The first flag is required to activate this module. It tells what is the
interface where to listen for packets and react accordingly.

The second flag can be specified multiple times. It installs pattern filters
that, when matched, cause this module to inject an NXDOMAIN reply.

The third flag is like the second except that it returns a valid DNS reply
of type A, class IN, where the IP address is 127.0.0.1.

The fourth flag can be specified multiple times. It installs a filter for which,
whenever the pattern is mached in a packet payload, a RST segment is injected.

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
