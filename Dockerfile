# syntax=docker/dockerfile:1

# how to build
# docker build --rm -f Dockerfile -t ovs-cni-mirror .
# docker run --rm -it --name ovs-cni-mirror -v $PWD/build:/out ovs-cni-mirror
# scp -i ~/<server-key-path> ./build/* <user>@<server-ip>:<remote-server-path>

FROM golang:1.17

WORKDIR /app

COPY . ./

RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GO111MODULE=on go build -o ./ -tags no_openssl -mod vendor ./cmd/...

ENTRYPOINT ./export.sh