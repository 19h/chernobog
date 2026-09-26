FROM chernobog-vmp-linux32:test

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++-i686-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /output
