#!/usr/bin/env python3


""" ./qa/telegram.py - main QA script for telegram

    This script performs a bunch of telegram tests under censored
    network conditions and verifies that the measurement is consistent
    with the expectations, by parsing the resulting JSONL. """

# TODO(bassosimone): I sometimes see tests failing with eof_error, which is
# probably caused by me using a mobile connection. I believe we should attempt
# to be strict here, because we're doing QA. But maybe I'm wrong?

import contextlib
import json
import os
import shlex
import subprocess
import sys
import urllib.parse


ALL_POP_IPS = (
    "149.154.175.50",
    "149.154.167.51",
    "149.154.175.100",
    "149.154.167.91",
    "149.154.171.5",
)


def execute(args):
    """ Execute a specified command """
    print("+", args)
    subprocess.run(args)


def execute_jafar(ooni_exe, outfile, args):
    """ Executes jafar """
    with contextlib.suppress(FileNotFoundError):
        os.remove(outfile)  # just in case
    execute([
        "./jafar",
        "-main-command", "%s -gno '%s' telegram" % (ooni_exe, outfile),
        "-main-user", os.environ["SUDO_USER"],
    ] + args)


def start_test(name):
    """ Print message informing user that a test is starting """
    print("\n")
    print("*", name)


def read_result(outfile):
    """ Reads the result of an experiment """
    return json.load(open(outfile, "rb"))


def test_keys(result):
    """ Returns just the test keys of a specific result """
    return result["test_keys"]


def execute_jafar_and_return_validated_test_keys(ooni_exe, outfile, args):
    """ Executes jafar and returns the validated parsed result, or throws
        an AssertionError if the result is not valid. """
    execute_jafar(ooni_exe, outfile, args)
    result = read_result(outfile)
    # TODO(bassosimone): we can write significantly more checks here
    assert isinstance(result["test_keys"], dict)
    tk = result["test_keys"]
    assert isinstance(tk["requests"], list)
    assert len(tk["requests"]) > 0
    for entry in tk["requests"]:
        assert isinstance(entry, dict)
        failure = entry["failure"]
        assert isinstance(failure, str) or failure is None
        assert isinstance(entry["request"], dict)
        assert isinstance(entry["response"], dict)
    assert isinstance(tk["tcp_connect"], list)
    assert len(tk["tcp_connect"]) > 0
    for entry in tk["tcp_connect"]:
        assert isinstance(entry, dict)
        assert isinstance(entry["ip"], str)
        assert isinstance(entry["port"], int)
        assert isinstance(entry["status"], dict)
        failure = entry["status"]["failure"]
        success = entry["status"]["success"]
        assert isinstance(failure, str) or failure is None
        assert isinstance(success, bool)
    return tk


def telegram_tcp_blocking_all(ooni_exe, outfile):
    """ Test case where all POPs are TCP/IP blocked """
    start_test("telegram_tcp_blocking_all")
    args = []
    for ip in ALL_POP_IPS:
        args.append("-iptables-reset-ip")
        args.append(ip)
    tk = execute_jafar_and_return_validated_test_keys(ooni_exe, outfile, args)
    assert tk["telegram_tcp_blocking"] == True
    assert tk["telegram_http_blocking"] == True
    assert tk["telegram_web_failure"] == None
    assert tk["telegram_web_status"] == "ok"
    for entry in tk["tcp_connect"]:
        assert entry["status"]["failure"] == (
            "connection_refused" if entry["ip"] in ALL_POP_IPS else None
        )
    for entry in tk["requests"]:
        url = urllib.parse.urlsplit(entry["request"]["url"])
        assert entry["failure"] == (
            "connection_refused" if url.hostname in ALL_POP_IPS else None
        )


def telegram_tcp_blocking_some(ooni_exe, outfile):
    """ Test case where some POPs are TCP/IP blocked """
    start_test("telegram_tcp_blocking_some")
    args = [
        "-iptables-reset-ip",
        ALL_POP_IPS[0],
    ]
    tk = execute_jafar_and_return_validated_test_keys(ooni_exe, outfile, args)
    assert tk["telegram_tcp_blocking"] == False
    assert tk["telegram_http_blocking"] == False
    assert tk["telegram_web_failure"] == None
    assert tk["telegram_web_status"] == "ok"
    for entry in tk["tcp_connect"]:
        assert entry["status"]["failure"] == (
            "connection_refused" if entry["ip"] == ALL_POP_IPS[0] else None
        )
    for entry in tk["requests"]:
        url = urllib.parse.urlsplit(entry["request"]["url"])
        assert entry["failure"] == (
            "connection_refused" if url.hostname == ALL_POP_IPS[0] else None
        )


def telegram_http_blocking_all(ooni_exe, outfile):
    """ Test case where all POPs are HTTP blocked """
    start_test("telegram_http_blocking_all")
    args = []
    for ip in ALL_POP_IPS:
        args.append("-iptables-reset-keyword")
        args.append(ip)
    tk = execute_jafar_and_return_validated_test_keys(ooni_exe, outfile, args)
    assert tk["telegram_tcp_blocking"] == False
    assert tk["telegram_http_blocking"] == True
    assert tk["telegram_web_failure"] == None
    assert tk["telegram_web_status"] == "ok"
    for entry in tk["tcp_connect"]:
        assert entry["status"]["failure"] == None
    for entry in tk["requests"]:
        url = urllib.parse.urlsplit(entry["request"]["url"])
        assert entry["failure"] == (
            "connection_reset" if url.hostname in ALL_POP_IPS else None
        )


def telegram_http_blocking_some(ooni_exe, outfile):
    """ Test case where some POPs are HTTP blocked """
    start_test("telegram_http_blocking_some")
    args = [
        "-iptables-reset-keyword",
        ALL_POP_IPS[0],
    ]
    tk = execute_jafar_and_return_validated_test_keys(ooni_exe, outfile, args)
    assert tk["telegram_tcp_blocking"] == False
    assert tk["telegram_http_blocking"] == False
    assert tk["telegram_web_failure"] == None
    assert tk["telegram_web_status"] == "ok"
    for entry in tk["tcp_connect"]:
        assert entry["status"]["failure"] == None
    for entry in tk["requests"]:
        url = urllib.parse.urlsplit(entry["request"]["url"])
        assert entry["failure"] == (
            "connection_reset" if url.hostname == ALL_POP_IPS[0] else None
        )


def telegram_web_failure_http(ooni_exe, outfile):
    """ Test case where the web HTTP endpoint is blocked """
    start_test("telegram_web_failure_http")
    args = [
        "-iptables-reset-keyword",
        "Host: web.telegram.org"
    ]
    tk = execute_jafar_and_return_validated_test_keys(ooni_exe, outfile, args)
    assert tk["telegram_tcp_blocking"] == False
    assert tk["telegram_http_blocking"] == False
    assert tk["telegram_web_failure"] == "connection_reset"
    assert tk["telegram_web_status"] == "blocked"
    for entry in tk["tcp_connect"]:
        assert entry["status"]["failure"] == None
    for entry in tk["requests"]:
        url = entry["request"]["url"]
        assert entry["failure"] == (
            "connection_reset" if url == "http://web.telegram.org/" else None
        )


def telegram_web_failure_https(ooni_exe, outfile):
    """ Test case where the web HTTPS endpoint is blocked """
    #
    #  00 00          <SNI extension ID>
    #  00 15          <full extension length>
    #  00 13          <first entry length>
    #  00             <DNS hostname type>
    #  00 10          <string length>
    #  77 65 ... 67   web.telegram.org
    #
    start_test("telegram_web_failure_https")
    args = [
        "-iptables-reset-keyword-hex",
        "|00 00 00 15 00 13 00 00 10 77 65 62 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67|"
    ]
    tk = execute_jafar_and_return_validated_test_keys(ooni_exe, outfile, args)
    assert tk["telegram_tcp_blocking"] == False
    assert tk["telegram_http_blocking"] == False
    assert tk["telegram_web_failure"] == "connection_reset"
    assert tk["telegram_web_status"] == "blocked"
    for entry in tk["tcp_connect"]:
        assert entry["status"]["failure"] == None
    for entry in tk["requests"]:
        url = entry["request"]["url"]
        assert entry["failure"] == (
            "connection_reset" if url == "https://web.telegram.org/" else None
        )


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: %s /path/to/ooniprobelegacy-like/binary" %
                 sys.argv[0])
    outfile = "telegram.jsonl"
    ooni_exe = sys.argv[1]
    tests = [
        telegram_tcp_blocking_all,
        telegram_tcp_blocking_some,
        telegram_http_blocking_all,
        telegram_http_blocking_some,
        telegram_web_failure_http,
        telegram_web_failure_https,
    ]
    for test in tests:
        test(ooni_exe, outfile)


if __name__ == "__main__":
    main()