## Makefile.am
AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS     = mkfs.erofs
mkfs_erofs_SOURCES = erofs_compressor.c \
		     mkfs_file.c \
		     erofs_lz4hc.c \
		     mkfs_main.c \
		     erofs_cache.c \
		     erofs_io.c \
		     mkfs_inode.c \
		     erofs_config.c

noinst_HEADERS = erofs_config.h  \
		 mkfs_inode.h \
		 erofs_error.h \
		 erofs_lz4hc.h \
		 erofs_cache.h \
		 erofs_debug.h \
		 mkfs_erofs.h \
		 erofs_compressor.h \
		 erofs_io.h \
		 mkfs_file.h

mkfs_erofs_CFLAGS = -Wall -Werror -DEROFS_MKFS_VERSION=\"v1.0\" -I$(top_srcdir)/include
ACLOCAL_AMFLAGS = -I m4

if SUPPORT_LARG_FILE_AT_BIT32
    mkfs_erofs_CFLAGS += -D_FILE_OFFSET_BITS=64
endif

