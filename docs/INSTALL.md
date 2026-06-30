# Building and Installing erofs-utils

## Dependencies

The following libraries are required or optional, depending on the features you want to enable:

* `zlib` for DEFLATE and GZIP support
* `libuuid` for UUID generation
* `LZ4` 1.9.3 or later for LZ4/LZ4HC support[^1]
* `libzstd` for Zstandard support
* `XZ Utils` 5.3.2alpha or later for MicroLZMA support (5.4 or later is strongly recommended)
* `libfuse` 2.6 or later, or `libfuse3`, for `erofsfuse`
* `libxml2` and `json-c` for OCI registry support
* `libcurl` and `OpenSSL` for S3 object storage support

[^1]: LZ4 versions earlier than 1.9.3 are not recommended due to known bugs in `LZ4_compress_destSize()`,
`LZ4_compress_HC_destSize()`, and `LZ4_decompress_safe_partial()`.

## Configure and Build

```sh
./autogen.sh
./configure
make
```

To display all available build options and their default values:

```sh
./configure --help
```

Many optional features can be controlled using `--enable-*`/`--disable-*` and `--with-*`/`--without-*` options.
For example:

```sh
./configure --enable-lz4 \
    --enable-lzma \
    --enable-fuse
```

Depending on the selected configuration, the following binaries may be built:

* `mkfs.erofs`
* `dump.erofs`
* `fsck.erofs`
* `mount.erofs`
* `erofsfuse`

## Install

```sh
sudo make install
```

By default, files are installed under `/usr/local`.
To install into a different location:

```sh
./configure --prefix=$HOME/.local
make
make install
```
