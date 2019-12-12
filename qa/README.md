# Quality Assurance scripts

This directory contains quality assurance scripts that use Jafar to
ensure that OONI implementations behave. These scripts take as unique
command line argument the path to a binary with a OONI Probe v2.x
compatible command line interface. Tools with this CLI are:

1. `github.com/ooni/probe-legacy`
2. `github.com/measurement-kit/measurement-kit/src/measurement_kit`
3. `github.com/ooni/probe-engine/cmd/miniooni`

These scripts assume you're on a Linux system with `iptables`, `bash`,
`python3`, and possibly a bunch of other tools installed.
