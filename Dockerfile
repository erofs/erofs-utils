# Build fully static erofs-utils binaries

FROM alpine:3.24.1 AS builder

RUN apk add --no-cache \
    build-base \
    autoconf \
    automake \
    libtool \
    pkgconfig \
    git \
    util-linux-dev util-linux-static \
    fuse3-dev fuse3-static \
    zlib-dev zlib-static \
    lz4-dev lz4-static \
    openssl-dev openssl-libs-static \
    xz-dev xz-static \
    zlib-dev zlib-static \
    zstd-dev zstd-static \
    libxml2-dev libxml2-static \
    json-c-dev liburing-dev \
    libnl3-dev libnl3-static \
    curl-static curl-dev brotli-static libidn2-static libpsl-static libunistring-static nghttp2-static \
    linux-headers

WORKDIR /build
COPY . .

RUN ./autogen.sh && \
    PKG_CONFIG="pkg-config --static" LDFLAGS="-static -no-pie" ./configure --enable-static --disable-shared \
        --prefix=$(pwd)/output \
        --enable-multithreading \
        --enable-fanotify \
        --enable-fuse \
        --enable-lz4 \
        --enable-lzma \
        --enable-s3 \
        --enable-oci \
        --enable-ublk \
        --with-json-c \
        --with-libcurl \
        --with-libnl3 \
        --with-libzstd \
        --with-libxml2 \
        --with-openssl \
        --with-uuid && \
    make -j"$(nproc)" V=1 LDFLAGS="-all-static" && make install

FROM scratch
COPY --from=builder /build/output .
