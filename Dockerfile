# Build static erofs-utils binaries:
#   docker build --target linux --output type=local,dest=output/linux .
#   docker build --target windows --output type=local,dest=output/windows .

ARG MINGW_BUILD_PLATFORM=linux/amd64

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

# Cross-compile x86-64 Windows binaries with static third-party libraries.
# Alpine packages the MinGW toolchain for x86-64 build hosts.
FROM --platform=${MINGW_BUILD_PLATFORM} alpine:3.24.1 AS windows-builder

RUN apk add --no-cache \
    build-base autoconf automake libtool pkgconf git \
    ca-certificates curl tar zstd mingw-w64-gcc

ENV MINGW_TARGET=x86_64-w64-mingw32 MINGW_PREFIX=/ucrt64
ENV CC=${MINGW_TARGET}-gcc \
    AR=${MINGW_TARGET}-ar \
    RANLIB=${MINGW_TARGET}-ranlib \
    WINDRES=${MINGW_TARGET}-windres

# Use MSYS2 UCRT64 archives with Alpine's UCRT-based MinGW toolchain.
# curl-winssl uses the Windows certificate store for HTTPS.
ARG MSYS2_MIRROR=https://repo.msys2.org/mingw/ucrt64
WORKDIR /deps
COPY scripts/msys2-ucrt64.sha256 .
RUN while read -r checksum package; do \
        curl -fLsS -o "$package" "${MSYS2_MIRROR}/$package" && \
        echo "$checksum  $package" | sha256sum -c - && \
        tar --zstd -xf "$package" -C / ucrt64 || exit 1; \
    done < msys2-ucrt64.sha256 && \
    find ${MINGW_PREFIX}/lib -name '*.dll.a' -delete

# Keep native pkg-config metadata out of cross checks.
ENV PKG_CONFIG_LIBDIR=${MINGW_PREFIX}/lib/pkgconfig PKG_CONFIG_PATH=""

WORKDIR /build
COPY . .
RUN ./autogen.sh && mkdir build-windows && cd build-windows && \
    PKG_CONFIG="pkg-config --static" \
    CPPFLAGS="-I${MINGW_PREFIX}/include -I${MINGW_PREFIX}/include/tre" \
    LDFLAGS="-static -L${MINGW_PREFIX}/lib" \
    LIBS="-lintl -liconv" \
    ../configure --host=${MINGW_TARGET} --prefix=/output \
        --enable-static --disable-shared --enable-multithreading \
        --enable-lz4 --enable-lzma --with-zlib --with-libzstd \
        --without-uuid --without-selinux \
        --enable-s3 --enable-oci \
        --with-libcurl --with-openssl --with-libxml2 --with-json-c \
        --without-libnl3 && \
    make -j"$(nproc)" V=1 LDFLAGS="-all-static -L${MINGW_PREFIX}/lib" && \
    make install-strip && \
    for binary in /output/bin/*.exe; do \
        ${MINGW_TARGET}-objdump -p "$binary" > /tmp/imports.txt && \
        awk '/DLL Name:/ { \
            name = tolower($3); \
            if (name !~ /^(kernel32|advapi32|msvcrt|ucrtbase|bcrypt|crypt32|secur32|ws2_32|iphlpapi|wldap32|user32|gdi32|api-ms-win-crt-[a-z0-9-]+)\.dll$/) { \
                print "Unexpected DLL dependency: " $3; failed = 1 \
            } \
        } END { exit failed }' /tmp/imports.txt || exit 1; \
    done

FROM scratch AS windows
COPY --from=windows-builder /output .

# Keep the existing Linux output as the default target.
FROM scratch AS linux
COPY --from=builder /build/output .
