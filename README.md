# Jafar

> We stepped up the game of simulating censorship upgrading from the
> evil genius to the evil grand vizier.

Jafar is a censorship simulation tool. Some of its functionality are more
easily coupled with github.com/ooni/netx.

We use Go >= 1.11. With:

```
go build -v .
```

you compile Jafar. You need to run Jafar as root.

The main flag you're interested to is `-censor <string>`. This flag may
be specified many times to configure more censored strings. The effect of
this flag is the following:

1. any non-localhost DNS query containing `<string>` should receive an
injected DNS reply pointing to `127.0.0.1`.

2. any non-localhost TCP segment towards ports 80 or 443 containing
`<string>` will be replied to with an RST segment.

3. any query directed to the local DNS proxy containing `<string>` will
receive a NXDOMAIN response.

4. any request directed to the local transparent HTTP proxy containing
`<string>` in the `Host` header will receive a 451 response.

5. any TLS handshake directed to the local transparent TLS proxy
containing `<string>` in the SNI will be ???.

See `./jafar -help` for more tunable flags.
