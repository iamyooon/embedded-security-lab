FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    softhsm2 opensc libengine-pkcs11-openssl openssl u-boot-tools device-tree-compiler gdb procps gcc libc6-dev libp11-kit-dev python3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
