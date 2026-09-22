FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG LLVM_MAJOR=20
ARG XWIN_VERSION=0.8.0

RUN apt-get update && apt-get install -y \
    ca-certificates \
    cmake \
    curl \
    git \
    gpg \
    ninja-build \
    python3 \
    tar \
    wget \
    xz-utils && \
    rm -rf /var/lib/apt/lists/*

RUN . /etc/os-release && \
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key > /etc/apt/trusted.gpg.d/apt.llvm.org.asc && \
    echo "deb http://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-${LLVM_MAJOR} main" > /etc/apt/sources.list.d/llvm.list && \
    apt-get update && apt-get install -y \
    clang-${LLVM_MAJOR} \
    libclang-rt-${LLVM_MAJOR}-dev \
    lld-${LLVM_MAJOR} \
    llvm-${LLVM_MAJOR} \
    llvm-${LLVM_MAJOR}-tools && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/Jake-Shadle/xwin/releases/download/${XWIN_VERSION}/xwin-${XWIN_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
    | tar -xz && \
    install -m 0755 "xwin-${XWIN_VERSION}-x86_64-unknown-linux-musl/xwin" /usr/local/bin/xwin && \
    rm -rf "xwin-${XWIN_VERSION}-x86_64-unknown-linux-musl"

COPY docker/prepare-llvm-shims.py /usr/local/bin/prepare-llvm-shims.py
COPY docker/run-windows-workflow.sh /usr/local/bin/run-windows-workflow

RUN chmod 0755 /usr/local/bin/prepare-llvm-shims.py /usr/local/bin/run-windows-workflow

ENV WORKSPACE=/workspace

WORKDIR /workspace

CMD ["/usr/local/bin/run-windows-workflow"]
