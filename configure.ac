#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([mkfs.erofs], [0.0.1], [bluce.liguifu@huawei.com])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_SRCDIR([mkfs_main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL


# checks system architecture firtly for enable support larg file
ARCH_BIT=`getconf LONG_BIT`
AM_CONDITIONAL([SUPPORT_LARG_FILE_AT_BIT32],[test x$ARCH_BIT = x32])

# Checks for libraries.
# Ask user for path to liblz4.a stuff:.
AC_ARG_WITH(lz4,
    [ --with-lz4=<path> prefix of liblz4.a installation. e.g. /usr/local or /usr],
    [LIBLZ4_STATIC=$with_lz4/liblz4.a],
    AC_MSG_ERROR([You must call configure with the --with-lz4 option.
    This tells configure where to find the MySql C library and headers.
    e.g. --with-lz4=/usr/local or --with-lz4=/usr])
)

AC_SUBST(LIBLZ4_STATIC)

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h stddef.h stdint.h stdlib.h string.h sys/time.h unistd.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([ftruncate getcwd gettimeofday memset realpath strdup strerror strrchr strtoull])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
