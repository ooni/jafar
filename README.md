# Jafar

> We stepped up the game of simulating censorship upgrading from the
> evil genius to the evil grand vizier.

Jafar is a censorship simulation tool. Some of its functionality are more
easily coupled with github.com/ooni/netx.

We use Go >= 1.11. With:

```
go build -v .
```

you compile Jafar. You need to run Jafar as root. You can get a complete list
of all flags using `./jafar -help`. Read on for more detailed help.

Jafar is composed of modules. Each modules is controllable via flags.

## module: pktinjector

This module sniffs packets on one or more interfaces. Use
`-pktinjector-interface`, possibly multiple times, to specify
which interface(s) to use. Otherwise, we'll pick all interfaces
with an assigned IPv4 different from `127.0.0.1`.

The `-pktinjector-rst <value>` flag adds a rule such that we
will inject a RST segment whenever we see `<value>` inside an
outgoing TCP segment query.

## module: resolver

This module is a stub resolver. You should configure it as your
resolver on your system to simulate censorship.

By default, the resolver listens on `127.0.0.1:53` and you can use the
`-resolver-address <address>` flag to change that. It will forward
all queries to the configured DNS upstream (`8.8.8.8:53` by default,
use the `-resolver-upstream` to change that).

The `-resolver-blackhole <value>` flag adds a rule such that the
resolver returns `127.0.0.2` for queries containing `<value>`.

The `-resolver-block <value>` is like above but returns `NXDOMAIN`.

The `-resolver-hijack <value>` is like above but redirects on
`127.0.0.1` where we have `httpproxy` and `tlsproxy`.

## module: httpproxy

When you use DNS-injection-based hijacking (see above) you are redirected
to `127.0.0.1`. The httpproxy module is here for taking care of these
redirected requests. If you used any `-httpproxy-block <value>`, we
will return `451` if the `Host` header contains `<value>`. Otherwise,
we'll use the `Host` header to issue a request and return you the
corresponding HTTP response. We listen on `127.0.0.1:80` by default
and you can use `-httpproxy-address <address>` to change that.

## module: tlsproxy

This module is like `httpproxy` except that it uses SNI to find
out what server to connect to, rather than the `Host` header.
