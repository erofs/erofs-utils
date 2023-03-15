# Test setup

Processor: x86_64, Intel(R) Xeon(R) Platinum 8369B CPU @ 2.70GHz * 2 VCores

Storage: Cloud disk, 3000 IOPS upper limit

OS Kernel: Linux 6.2

Software: LZ4 1.9.3, erofs-utils 1.6, squashfs-tools 4.5.1

Disclaimer: Test results could be varied from different hardware and/or data patterns. Therefore, the following results are **ONLY for reference**.

# Benchmark on multiple files

[Rootfs of Debian docker image](https://github.com/debuerreotype/docker-debian-artifacts/blob/dist-amd64/bullseye/rootfs.tar.xz?raw=true) is used as the dataset, which contains 7000+ files and directories.
Note that that dataset can be replaced regularly, and the SHA1 of the snapshot "rootfs.tar.xz" used here is "aee9b01a530078dbef8f08521bfcabe65b244955".

## Image size

|   Size    | Filesystem | Cluster size | Build options                                                  |
|-----------|------------|--------------|----------------------------------------------------------------|
| 124669952 | erofs      | uncompressed | -T0 [^1]                                                       |
| 124522496 | squashfs   | uncompressed | -noD -noI -noX -noF -no-xattrs -all-time 0 -no-duplicates [^2] |
|  73601024 | squashfs   | 4096         | -b 4096 -comp lz4 -Xhc -no-xattrs -all-time 0                  |
|  73121792 | erofs      | 4096         | -zlz4hc,12 [^3] -C4096 -Efragments -T0                         |
|  67162112 | squashfs   | 16384        | -b 16384 -comp lz4 -Xhc -no-xattrs -all-time 0                 |
|  65478656 | erofs      | 16384        | -zlz4hc,12 -C16384 -Efragments -T0                             |
|  61456384 | squashfs   | 65536        | -b 65536 -comp lz4 -Xhc -no-xattrs -all-time 0                 |
|  59834368 | erofs      | 65536        | -zlz4hc,12 -C65536 -Efragments -T0                             |
|  59150336 | squashfs   | 131072       | -b 131072 -comp lz4 -Xhc -no-xattrs -all-time 0                |
|  58515456 | erofs      | 131072       | -zlz4hc,12 -C131072 -Efragments -T0                            |

[^1]: Forcely reset all timestamps to match squashfs on-disk basic inodes for now.
[^2]: Currently erofs-utils doesn't actively de-duplicate identical files although the on-disk format supports this.
[^3]: Because squashfs uses level 12 for LZ4HC by default.

## Sequential data access

```bash
hyperfine -p "echo 3 > /proc/sys/vm/drop_caches; sleep 1" "tar cf - . | cat > /dev/null"
```

| Filesystem | Cluster size | Time                            |
|------------|--------------|---------------------------------|
| squashfs   | 4096         | 10.257 s ±  0.031 s             |
| erofs      | uncompressed |  1.111 s ±  0.022 s             |
| squashfs   | uncompressed |  1.034 s ±  0.020 s             |
| squashfs   | 131072       | 941.3 ms ±   7.5 ms             |
| erofs      | 4096         | 848.1 ms ±  17.8 ms             |
| erofs      | 131072       | 724.2 ms ±  11.0 ms             |

## Sequential metadata access

```bash
hyperfine -p "echo 3 > /proc/sys/vm/drop_caches; sleep 1" "tar cf /dev/null ."
```

| Filesystem | Cluster size | Time                            |
|------------|--------------|---------------------------------|
| erofs      | uncompressed | 419.6 ms ±   8.2 ms             |
| squashfs   | 4096         | 142.5 ms ±   5.4 ms             |
| squashfs   | uncompressed | 129.2 ms ±   3.9 ms             |
| squashfs   | 131072       | 125.4 ms ±   4.0 ms             |
| erofs      | 4096         |  75.5 ms ±   3.5 ms             |
| erofs      | 131072       |  65.8 ms ±   3.6 ms             |

[ Note that erofs-utils currently doesn't perform quite well for such cases due to metadata arrangement when building.  It will be fixed in the later versions. ]

## Small random data access (~7%)

```bash
find mnt -type f -printf "%p\n" | sort -R | head -n 500 > list.txt
hyperfine -p "echo 3 > /proc/sys/vm/drop_caches; sleep 1" "cat list.txt | xargs cat > /dev/null"
```

| Filesystem | Cluster size | Time                            |
|------------|--------------|---------------------------------|
| squashfs   | 4096         |  1.386 s ±  0.032 s             |
| squashfs   | uncompressed |  1.083 s ±  0.044 s             |
| squashfs   | 131072       |  1.067 s ±  0.046 s             |
| erofs      | 4096         | 249.6 ms ±   6.5 ms             |
| erofs      | uncompressed | 237.8 ms ±   6.3 ms             |
| erofs      | 131072       | 189.6 ms ±   7.8 ms             |


## Small random metadata access (~7%)

```bash
find mnt -type f -printf "%p\n" | sort -R | head -n 500 > list.txt
hyperfine -p "echo 3 > /proc/sys/vm/drop_caches; sleep 1" "cat list.txt | xargs stat"
```

| Filesystem | Cluster size | Time                            |
|------------|--------------|---------------------------------|
| squashfs   | 4096         | 817.0 ms ±  34.5 ms             |
| squashfs   | 131072       | 801.0 ms ±  40.1 ms             |
| squashfs   | uncompressed | 741.3 ms ±  18.2 ms             |
| erofs      | uncompressed | 197.8 ms ±   4.1 ms             |
| erofs      | 4096         |  63.1 ms ±   2.0 ms             |
| erofs      | 131072       |  60.7 ms ±   3.6 ms             |

## Full random data access (~100%)

```bash
find mnt -type f -printf "%p\n" | sort -R > list.txt
hyperfine -p "echo 3 > /proc/sys/vm/drop_caches; sleep 1" "cat list.txt | xargs cat > /dev/null"
```

| Filesystem | Cluster size | Time                            |
|------------|--------------|---------------------------------|
| squashfs   | 4096         | 20.668 s ±  0.040 s             |
| squashfs   | uncompressed | 12.543 s ±  0.041 s             |
| squashfs   | 131072       | 11.753 s ±  0.412 s             |
| erofs      | uncompressed |  1.493 s ±  0.023 s             |
| erofs      | 4096         |  1.223 s ±  0.013 s             |
| erofs      | 131072       | 598.2 ms ±   6.6 ms             |

## Full random metadata access (~100%)

```bash
find mnt -type f -printf "%p\n" | sort -R > list.txt
hyperfine -p "echo 3 > /proc/sys/vm/drop_caches; sleep 1" "cat list.txt | xargs stat"
```

| Filesystem | Cluster size | Time                            |
|------------|--------------|---------------------------------|
| squashfs   | 131072       |  9.212 s ±  0.467 s             |
| squashfs   | 4096         |  8.905 s ±  0.147 s             |
| squashfs   | uncompressed |  7.961 s ±  0.045 s             |
| erofs      | 4096         | 661.2 ms ±  14.9 ms             |
| erofs      | uncompressed | 125.8 ms ±   6.6 ms             |
| erofs      | 131072       | 119.6 ms ±   5.5 ms             |


# FIO benchmark on a single large file

`silesia.tar` (203M) is used to benchmark, which could be generated from unzipping [silesia.zip](http://mattmahoney.net/dc/silesia.zip) and tar.

## Image size

|   Size    | Filesystem | Cluster size | Build options                                             |
|-----------|------------|--------------|-----------------------------------------------------------|
| 114339840 | squashfs   | 4096         | -b 4096 -comp lz4 -Xhc -no-xattrs                         |
| 104972288 | erofs      | 4096         | -zlz4hc,12 -C4096                                         |
|  98033664 | squashfs   | 16384        | -b 16384 -comp lz4 -Xhc -no-xattrs                        |
|  89571328 | erofs      | 16384        | -zlz4hc,12 -C16384                                        |
|  85143552 | squashfs   | 65536        | -b 65536 -comp lz4 -Xhc -no-xattrs                        |
|  81211392 | squashfs   | 131072       | -b 131072 -comp lz4 -Xhc -no-xattrs                       |
|  80519168 | erofs      | 65536        | -zlz4hc,12 -C65536                                        |
|  78888960 | erofs      | 131072       | -zlz4hc,12 -C131072                                       |

## Sequential I/Os

```bash
fio -filename=silesia.tar -bs=4k -rw=read -name=job1
```

| Filesystem | Cluster size | Bandwidth |
|------------|--------------|-----------|
| erofs      | 65536        | 624 MiB/s |
| erofs      | 16384        | 600 MiB/s |
| erofs      | 4096         | 569 MiB/s |
| erofs      | 131072       | 535 MiB/s |
| squashfs   | 131072       | 236 MiB/s |
| squashfs   | 65536        | 157 MiB/s |
| squashfs   | 16384        | 55.2MiB/s |
| squashfs   | 4096         | 12.5MiB/s |

## Full Random I/Os

```bash
fio -filename=silesia.tar -bs=4k -rw=randread -name=job1
```

| Filesystem | Cluster size | Bandwidth |
|------------|--------------|-----------|
| erofs      | 131072       | 242 MiB/s |
| squashfs   | 131072       | 232 MiB/s |
| erofs      | 65536        | 198 MiB/s |
| squashfs   | 65536        | 150 MiB/s |
| erofs      | 16384        | 96.4MiB/s |
| squashfs   | 16384        | 49.5MiB/s |
| erofs      | 4096         | 33.7MiB/s |
| squashfs   | 4096         | 6817KiB/s |

## Small Random I/Os (~5%)

```bash
fio -filename=silesia.tar -bs=4k -rw=randread --io_size=10m -name=job1
```

| Filesystem | Cluster size | Bandwidth |
|------------|--------------|-----------|
| erofs      | 131072       | 19.2MiB/s |
| erofs      | 65536        | 16.9MiB/s |
| squashfs   | 131072       | 15.1MiB/s |
| erofs      | 16384        | 14.7MiB/s |
| squashfs   | 65536        | 13.8MiB/s |
| erofs      | 4096         | 13.0MiB/s |
| squashfs   | 16384        | 11.7MiB/s |
| squashfs   | 4096         | 4376KiB/s |
