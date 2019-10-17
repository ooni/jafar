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

This module sniffs packets on one or more interfaces. Use `-censor-interface`
to specify which interface(s) to use. Otherwise, we'll pick all interfaces with
an assigned IPv4 different from `127.0.0.1`.

The `-censor-with-dns-injection <value>` flag adds a rule such that we'll
send a DNS injection response for `127.0.0.1` whenever we see `<value`>`
inside an outgoing DNS query. The `-censor-with-rst-injection <value>` is
similar but operates on TCP segments.

## module: httpproxy

When you `-censor-with-dns-injection <value>` you are redirected to
`127.0.0.1`. The httpproxy module is here for taking care of these
redirected requests. If you used any `-httpproxy-blocked <value>`, we
will return `451` if the `Host` header contains `<value>`. Otherwise,
we'll use the `Host` header to issue a request and return you the
corresponding HTTP response. We listen on `127.0.0.1:80` by default
and you can use `-httpproxy-address <address>` to change that.

## module: resolver

The DNS injection implementation returns a bogus IP address by
default. To test the case where a server returns `NXDOMAIN` for
a resource, you can use the builtin DNS resolver. By default,
it listens on `127.0.0.1:53` and you can use `-resolver-address
<address>` to change that. It will forward all queries to the
configured DNS upstream (`8.8.8.8:53` by default, use the
`-resolver-upstream` to change that). However, if you have
specified one or more `-resolver-blocked <value>` flags and
the DNS query contains a `<value>`, the query won't be forwarded
to the upstream. Instead we'll return `NXDOMAIN` immediately.
