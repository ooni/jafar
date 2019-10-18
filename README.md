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

## module: iptables

This module use iptables rules to drop or reject packets. The
`-iptables-drop <ip|string>` flag adds a rule that drops packets. If
the argument is an `ip`, then packets having that IP as destination
are dropped. Otherwise, we drop packets containing `<string>`.

The `-iptables-rst <value>` flag is similar except that it sends a RST
segment to forcibly terminate a specifc flow.

The `-iptables-route-dns-to <address>` flag is active by default and
redirects any DNS traffic not run by root to the resolver model, so that
we can have a chance of applying censorship policies.

## module: resolver

This module is a stub resolver. You should configure it as your
resolver on your system to simulate censorship.

By default, the resolver listens on `127.0.0.1:53` and you can use the
`-resolver-address <address>` flag to change that. It will forward
all queries to the configured DNS upstream (`8.8.8.8:53` by default,
use the `-resolver-upstream` to change that).

The `-resolver-hijack <value>` flag adds a rule such that the
resolver returns `127.0.0.1` for queries containing `<value>`, thus
directing traffic to `httpproxy` and `tlsproxy`.

The `-resolver-block <value>` is like above but returns `NXDOMAIN`.

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
