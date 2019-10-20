FROM alpine:edge
RUN apk add go git musl-dev iptables tmux bind-tools curl
ENV GOPATH=/go
