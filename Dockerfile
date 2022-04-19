# syntax=docker/dockerfile:1

# how to build
# docker build --rm -f Dockerfile -t ovs-cni-mirror-producer .
# docker run --rm -it --name ovs-cni-mirror-producer -v $PWD/build:/out ovs-cni-mirror-producer
# kill the process and check ./build folder with the resulting marker and plugin binary files

# copy to the server `cp plugin /opt/cni/bin/ovs-cni-mirror-producer`

FROM golang:1.16

WORKDIR /app

COPY . ./

RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GO111MODULE=on go build -o ./ -tags no_openssl -mod vendor ./cmd/...

ENTRYPOINT ./export.sh