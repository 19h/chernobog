FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-i686-linux-gnu binutils-i686-linux-gnu libc6-dev-i386-cross \
    qemu-user python3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /output
