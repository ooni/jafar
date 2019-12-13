#!/bin/sh
set -ex
DOCKER=${DOCKER:-docker}
$DOCKER build -t jafar-qa .
$DOCKER run --privileged -it -v`pwd`:/jafar -w/jafar jafar-qa
