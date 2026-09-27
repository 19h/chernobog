# Build context contains the official qemu-9.2.0.tar.xz source archive.
# Inspect BASE_IMAGE and record its immutable image ID before building.
ARG BASE_IMAGE=chernobog-vmp-linux32:test
FROM ${BASE_IMAGE} AS qemu-build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ninja-build pkg-config python3-venv \
    libglib2.0-dev libpixman-1-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY qemu-9.2.0.tar.xz /tmp/qemu-9.2.0.tar.xz
RUN echo 'f859f0bc65e1f533d040bbe8c92bcfecee5af2c921a6687c652fb44d089bd894  /tmp/qemu-9.2.0.tar.xz' | sha256sum -c - \
    && mkdir /tmp/qemu \
    && tar -xJf /tmp/qemu-9.2.0.tar.xz --strip-components=1 -C /tmp/qemu \
    && cd /tmp/qemu \
    && ./configure --target-list=i386-linux-user --disable-system --enable-linux-user \
        --disable-docs --disable-tools --disable-guest-agent --disable-plugins \
        --disable-slirp --disable-capstone --disable-werror \
    && ninja -C build -j 20 qemu-i386 \
    && build/qemu-i386 --version

FROM ${BASE_IMAGE}
COPY --from=qemu-build /tmp/qemu/build/qemu-i386 /usr/bin/qemu-i386
RUN qemu-i386 --version
WORKDIR /output
