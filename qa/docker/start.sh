#!/bin/sh
set -ex
docker build -t jafar-qa .
docker run --privileged -it -v`pwd`:/jafar -w/jafar jafar-qa
