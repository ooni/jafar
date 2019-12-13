#!/bin/sh
set -ex
(
  cd /
  CGO_ENABLED=0 go get -v github.com/ooni/probe-engine/cmd/miniooni@master
)
go build -v .
sudo ./qa/telegram/telegram.py $GOPATH/bin/miniooni
