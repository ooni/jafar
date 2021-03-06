# Quality Assurance scripts

This directory contains quality assurance scripts that use Jafar to
ensure that OONI implementations behave. These scripts take as unique
command line argument the path to a binary with a OONI Probe v2.x
compatible command line interface.

Tools with this CLI are:

1. `github.com/ooni/probe-legacy`
2. `github.com/measurement-kit/measurement-kit/src/measurement_kit`
3. `github.com/ooni/probe-engine/cmd/miniooni`

## Run QA on a Linux system

These scripts assume you're on a Linux system with `iptables`, `bash`,
`python3`, and possibly a bunch of other tools installed.

To start the QA script, run this command:

```bash
sudo ./qa/$nettest/$nettest.py $ooni_exe
```

where `$nettest` is the nettest name (e.g. `telegram`) and `$ooni_exe`
is the OONI Probe v2.x compatible binary to test.

The Python script needs to run as root. Note however that sudo will also
be used to run `$ooni_exe` with the privileges of the `$SUDO_USER` that
called `sudo ./qa/$nettest/$nettest.py ...`.

## Run QA using a docker container

Build and start a suitable docker container using:

```
./qa/docker/start.sh
```

Note that this will run a `--privileged` docker container. Once you have
started the container, then run:

```
./qa/docker/$nettest.sh
```

This will eventually run the Python script you would run on Linux.

For now, the docker scripts only perform QA of `miniooni`.

## Diagnosing issues

The Python script that performs the QA runs a specific OONI test under
different failure conditions and stops at the first unexpected value found
in the resulting JSONL report. You can infer what went wrong by reading
the output of the `$ooni_exe` command itself, which should be above the point
where the Python script stopped, as well as by inspecting the JSONL file on
disk. By convention such file is named `$nettest.jsonl` and only contains
the result of the last run of `$nettest`.
