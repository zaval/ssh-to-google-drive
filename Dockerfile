# syntax=docker/dockerfile:1
FROM ubuntu:24.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
COPY . /app
WORKDIR /app
RUN apt-get update && apt-get install -y gcc g++ cmake git libssl-dev libidn2-dev libz-dev libbrotli-dev libzstd-dev libnghttp2-dev libpsl-dev libssh-dev
RUN cmake -DCMAKE_BUILD_TYPE=Release -S . -B build && \
    cmake --build build -j$(nproc --all) && \
    cmake --install build

FROM ubuntu:24.04
WORKDIR /app
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=build /usr/local /usr/local
RUN apt-get update && apt-get install -y ca-certificates openssl libssl3t64 libidn2-0 zlib1g libbrotli1 libzstd1 libnghttp2-14 libpsl5t64 libssh-4 && rm -rf /var/lib/apt/lists/*

CMD ["/usr/local/bin/ssh_to_gdrive"]