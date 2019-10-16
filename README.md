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

The `pktinjector` module will listen on a specific interface and inject
NXDOMAIN DNS responses or TCP RST segments when it encounters specific
keywords. This mechanism is not deterministic, but does not require you
to modify in any way the censorship measurement tool you're testing.

The `dnsproxy` module is a DNS recursive resolver that you can configure
to return NXDOMAIN, or to return `127.0.0.1` when specific keywords
match the DNS query name. To use this functionality, you need to tell
the tool to use this module as its DNS (by default on `127.0.0.1:53/udp`).

The `connectproxy` is an HTTP CONNECT proxy. If it encounters specific
keywords inside the first chunk of bytes it reads, it will close and
attempt to RST the connection. This functionality is tightly coupled with
github.com/ooni/netx `OONI_NETX_PROXY` environment variable. This tells
netx to use the DNS but to connect using the specifed proxy and it allows
us to simulate an in-path transparent TCP proxy. Another option would be
to use `HTTP_PROXY=127.0.0.1:8080` (where `127.0.0.1:8080` is the address
where ths module listens). But in this case we would delegate also the
domain resolution to a proxy, which is another scenario.
