FROM alpine:edge
RUN apk add go git musl-dev iptables
ENV GOPATH=/go
RUN go get github.com/mattn/goveralls
ADD . /go/src/github.com/ooni/jafar
WORKDIR /go/src/github.com/ooni/jafar
CMD go test -coverprofile=jafar.cov -coverpkg=./... ./... &&                   \
    /go/bin/goveralls -coverprofile=jafar.cov -service=travis-ci