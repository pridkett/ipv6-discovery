FROM golang:1.16-alpine as build
WORKDIR /go/build
COPY *.go go.mod go.sum /go/build
RUN go build

FROM alpine:latest
COPY --from=build /go/build/ipv6-discoery /go/bin/ipv6-discovery
