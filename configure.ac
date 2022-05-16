#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])

m4_define([erofs_utils_version], m4_esyscmd_s([scripts/get-version-number]))
m4_define([erofs_utils_date], m4_esyscmd([sed -n '2p' VERSION | tr -d '\n']))

AC_INIT([erofs-utils], [erofs_utils_version], [linux-erofs@lists.ozlabs.org])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign -Wall])

# Checks for programs.
AM_PROG_AR
AC_PROG_CC
AC_PROG_INSTALL

LT_INIT

# Test presence of pkg-config
AC_MSG_CHECKING([pkg-config m4 macros])
if test m4_ifdef([PKG_CHECK_MODULES], [yes], [no]) = "yes"; then
  AC_MSG_RESULT([yes]);
else
  AC_MSG_RESULT([no]);
  AC_MSG_ERROR([pkg-config is required. See pkg-config.freedesktop.org])
fi

dnl EROFS_UTILS_PARSE_DIRECTORY
dnl Input:  $1 = a string to a relative or absolute directory
dnl Output: $2 = the variable to set with the absolute directory
AC_DEFUN([EROFS_UTILS_PARSE_DIRECTORY],
[
 dnl Check if argument is a directory
 if test -d $1 ; then
    dnl Get the absolute path of the directory
    dnl in case of relative directory.
    dnl If realpath is not a valid command,
    dnl an error is produced and we keep the given path.
    local_tmp=`realpath $1 2>/dev/null`
    if test "$local_tmp" != "" ; then
       if test -d "$local_tmp" ; then
           $2="$local_tmp"
       else
           $2=$1
       fi
    else
       $2=$1
    fi
    dnl Check for space in the directory
    if test `echo $1|cut -d' ' -f1` != $1 ; then
        AC_MSG_ERROR($1 directory shall not contain any space.)
    fi
 else
    AC_MSG_ERROR($1 shall be a valid directory)
 fi
])

AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
                    [enable debugging mode @<:@default=no@:>@])],
    [enable_debug="$enableval"],
    [enable_debug="no"])

AC_ARG_ENABLE([werror],
    [AS_HELP_STRING([--enable-werror],
                    [enable -Werror @<:@default=no@:>@])],
    [enable_werror="$enableval"],
    [enable_werror="no"])

AC_ARG_ENABLE(lz4,
   [AS_HELP_STRING([--disable-lz4], [disable LZ4 compression support @<:@default=enabled@:>@])],
   [enable_lz4="$enableval"], [enable_lz4="yes"])

AC_ARG_ENABLE(lzma,
   [AS_HELP_STRING([--enable-lzma], [enable LZMA compression support @<:@default=no@:>@])],
   [enable_lzma="$enableval"], [enable_lzma="no"])

AC_ARG_ENABLE(fuse,
   [AS_HELP_STRING([--enable-fuse], [enable erofsfuse @<:@default=no@:>@])],
   [enable_fuse="$enableval"], [enable_fuse="no"])

AC_ARG_WITH(uuid,
   [AS_HELP_STRING([--without-uuid],
      [Ignore presence of libuuid and disable uuid support @<:@default=enabled@:>@])])

AC_ARG_WITH(selinux,
   [AS_HELP_STRING([--with-selinux],
      [enable and build with selinux support @<:@default=no@:>@])],
   [case "$with_selinux" in
      yes|no) ;;
      *) AC_MSG_ERROR([invalid argument to --with-selinux])
      ;;
    esac], [with_selinux=no])

# Checks for libraries.
# Use customized LZ4 library path when specified.
AC_ARG_WITH(lz4-incdir,
   [AS_HELP_STRING([--with-lz4-incdir=DIR], [LZ4 include directory])], [
   EROFS_UTILS_PARSE_DIRECTORY(["$withval"],[withval])])

AC_ARG_WITH(lz4-libdir,
   [AS_HELP_STRING([--with-lz4-libdir=DIR], [LZ4 lib directory])], [
   EROFS_UTILS_PARSE_DIRECTORY(["$withval"],[withval])])

AC_ARG_VAR([LZ4_CFLAGS], [C compiler flags for lz4])
AC_ARG_VAR([LZ4_LIBS], [linker flags for lz4])

AC_ARG_WITH(liblzma-incdir,
   [AS_HELP_STRING([--with-liblzma-incdir=DIR], [liblzma include directory])], [
   EROFS_UTILS_PARSE_DIRECTORY(["$withval"],[withval])])

AC_ARG_WITH(liblzma-libdir,
   [AS_HELP_STRING([--with-liblzma-libdir=DIR], [liblzma lib directory])], [
   EROFS_UTILS_PARSE_DIRECTORY(["$withval"],[withval])])

# Checks for header files.
AC_CHECK_HEADERS(m4_flatten([
	dirent.h
	execinfo.h
	fcntl.h
	getopt.h
	inttypes.h
	linux/falloc.h
	linux/fs.h
	linux/types.h
	linux/xattr.h
	limits.h
	stddef.h
	stdint.h
	stdlib.h
	string.h
	sys/ioctl.h
	sys/stat.h
	sys/sysmacros.h
	sys/time.h
	unistd.h
]))

AC_HEADER_TIOCGWINSZ

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_MEMBERS([struct stat.st_atim])
AC_CHECK_MEMBERS([struct stat.st_atimensec])
AC_TYPE_UINT64_T

#
# Check to see if llseek() is declared in unistd.h.  On some libc's
# it is, and on others it isn't..... Thank you glibc developers....
#
AC_CHECK_DECL(llseek,
  [AC_DEFINE(HAVE_LLSEEK_PROTOTYPE, 1,
    [Define to 1 if llseek declared in unistd.h])],,
  [#include <unistd.h>])

#
# Check to see if lseek64() is declared in unistd.h.  Glibc's header files
# are so convoluted that I can't tell whether it will always be defined,
# and if it isn't defined while lseek64 is defined in the library,
# disaster will strike.
#
# Warning!  Use of --enable-gcc-wall may throw off this test.
#
AC_CHECK_DECL(lseek64,[AC_DEFINE(HAVE_LSEEK64_PROTOTYPE, 1,
  [Define to 1 if lseek64 declared in unistd.h])],,
  [#define _LARGEFILE_SOURCE
   #define _LARGEFILE64_SOURCE
   #include <unistd.h>])

AC_CHECK_DECL(memrchr,[AC_DEFINE(HAVE_MEMRCHR, 1,
  [Define to 1 if memrchr declared in string.h])],,
  [#define _GNU_SOURCE
   #include <string.h>])

# Checks for library functions.
AC_CHECK_FUNCS(m4_flatten([
	backtrace
	copy_file_range
	fallocate
	gettimeofday
	lgetxattr
	llistxattr
	memset
	realpath
	pread64
	pwrite64
	strdup
	strerror
	strrchr
	strtoull
	tmpfile64
	utimensat]))

# Configure debug mode
AS_IF([test "x$enable_debug" != "xno"], [], [
  dnl Turn off all assert checking.
  CPPFLAGS="$CPPFLAGS -DNDEBUG"
])

# Configure -Werror
AS_IF([test "x$enable_werror" != "xyes"], [], [
  CPPFLAGS="$CPPFLAGS -Werror"
])

# Configure libuuid
AS_IF([test "x$with_uuid" != "xno"], [
  PKG_CHECK_MODULES([libuuid], [uuid])
  # Paranoia: don't trust the result reported by pkgconfig before trying out
  saved_LIBS="$LIBS"
  saved_CPPFLAGS=${CPPFLAGS}
  CPPFLAGS="${libuuid_CFLAGS} ${CPPFLAGS}"
  LIBS="${libuuid_LIBS} $LIBS"
  AC_MSG_CHECKING([libuuid usability])
  AC_TRY_LINK([
#include <uuid.h>
], [
uuid_t tmp;

uuid_generate(tmp);
return 0;
], [have_uuid="yes"
    AC_MSG_RESULT([yes])], [
    have_uuid="no"
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([libuuid doesn't work properly])])
  LIBS="${saved_LIBS}"
  CPPFLAGS="${saved_CPPFLAGS}"], [have_uuid="no"])

# Configure selinux
AS_IF([test "x$with_selinux" != "xno"], [
  PKG_CHECK_MODULES([libselinux], [libselinux])
  # Paranoia: don't trust the result reported by pkgconfig before trying out
  saved_LIBS="$LIBS"
  saved_CPPFLAGS=${CPPFLAGS}
  CPPFLAGS="${libselinux_CFLAGS} ${CPPFLAGS}"
  LIBS="${libselinux_LIBS} $LIBS"
  AC_CHECK_LIB(selinux, selabel_lookup, [
    have_selinux="yes" ], [
    AC_MSG_ERROR([libselinux doesn't work properly])])
  LIBS="${saved_LIBS}"
  CPPFLAGS="${saved_CPPFLAGS}"], [have_selinux="no"])

# Configure fuse
AS_IF([test "x$enable_fuse" != "xno"], [
  PKG_CHECK_MODULES([libfuse], [fuse >= 2.6])
  # Paranoia: don't trust the result reported by pkgconfig before trying out
  saved_LIBS="$LIBS"
  saved_CPPFLAGS=${CPPFLAGS}
  CPPFLAGS="${libfuse_CFLAGS} ${CPPFLAGS}"
  LIBS="${libfuse_LIBS} $LIBS"
  AC_CHECK_LIB(fuse, fuse_main, [
    have_fuse="yes" ], [
    AC_MSG_ERROR([libfuse (>= 2.6) doesn't work properly])])
  LIBS="${saved_LIBS}"
  CPPFLAGS="${saved_CPPFLAGS}"], [have_fuse="no"])

# Configure lz4
test -z $LZ4_LIBS && LZ4_LIBS='-llz4'

if test "x$enable_lz4" = "xyes"; then
  test -z "${with_lz4_incdir}" || LZ4_CFLAGS="-I$with_lz4_incdir $LZ4_CFLAGS"

  saved_CPPFLAGS=${CPPFLAGS}
  CPPFLAGS="${LZ4_CFLAGS} ${CPPFLAGS}"

  AC_CHECK_HEADERS([lz4.h],[have_lz4h="yes"], [])

  if test "x${have_lz4h}" = "xyes" ; then
    saved_LIBS="$LIBS"
    saved_LDFLAGS=${LDFLAGS}
    test -z "${with_lz4_libdir}" || LDFLAGS="-L$with_lz4_libdir ${LDFLAGS}"
    AC_CHECK_LIB(lz4, LZ4_compress_destSize, [
      have_lz4="yes"
      have_lz4hc="yes"
      AC_CHECK_LIB(lz4, LZ4_compress_HC_destSize, [], [
        AC_CHECK_DECL(LZ4_compress_HC_destSize, [lz4_force_static="yes"],
          [have_lz4hc="no"], [[
#define LZ4_HC_STATIC_LINKING_ONLY (1)
#include <lz4hc.h>
        ]])
      ])
    ], [AC_MSG_ERROR([Cannot find proper lz4 version (>= 1.8.0)])])
    LDFLAGS=${saved_LDFLAGS}
    LIBS="${saved_LIBS}"
  fi
  CPPFLAGS=${saved_CPPFLAGS}
fi

if test "x$enable_lzma" = "xyes"; then
  saved_CPPFLAGS=${CPPFLAGS}
  test -z "${with_liblzma_incdir}" ||
    CPPFLAGS="-I$with_liblzma_incdir $CPPFLAGS"
  AC_CHECK_HEADERS([lzma.h],[have_lzmah="yes"], [])

  if test "x${have_lzmah}" = "xyes" ; then
    saved_LIBS="$LIBS"
    saved_LDFLAGS="$LDFLAGS"

    test -z "${with_liblzma_libdir}" ||
      LDFLAGS="-L$with_liblzma_libdir ${LDFLAGS}"
    AC_CHECK_LIB(lzma, lzma_microlzma_encoder, [],
      [AC_MSG_ERROR([Cannot find proper liblzma])])

    AC_CHECK_DECL(lzma_microlzma_encoder, [have_liblzma="yes"],
      [AC_MSG_ERROR([Cannot find proper liblzma])], [[
#include <lzma.h>
    ]])
    LDFLAGS="${saved_LDFLAGS}"
    LIBS="${saved_LIBS}"
  fi
  CPPFLAGS="${saved_CPPFLAGS}"
fi

# Set up needed symbols, conditionals and compiler/linker flags
AM_CONDITIONAL([ENABLE_LZ4], [test "x${have_lz4}" = "xyes"])
AM_CONDITIONAL([ENABLE_LZ4HC], [test "x${have_lz4hc}" = "xyes"])
AM_CONDITIONAL([ENABLE_FUSE], [test "x${have_fuse}" = "xyes"])
AM_CONDITIONAL([ENABLE_LIBLZMA], [test "x${have_liblzma}" = "xyes"])

if test "x$have_uuid" = "xyes"; then
  AC_DEFINE([HAVE_LIBUUID], 1, [Define to 1 if libuuid is found])
fi

if test "x$have_selinux" = "xyes"; then
  AC_DEFINE([HAVE_LIBSELINUX], 1, [Define to 1 if libselinux is found])
fi

if test "x${have_lz4}" = "xyes"; then
  AC_DEFINE([LZ4_ENABLED], [1], [Define to 1 if lz4 is enabled.])

  if test "x${have_lz4hc}" = "xyes"; then
    AC_DEFINE([LZ4HC_ENABLED], [1], [Define to 1 if lz4hc is enabled.])
  fi

  if test "x${lz4_force_static}" = "xyes"; then
    LZ4_LIBS="-Wl,-Bstatic -Wl,-whole-archive -Xlinker ${LZ4_LIBS} -Wl,-no-whole-archive -Wl,-Bdynamic"
    test -z "${with_lz4_libdir}" || LZ4_LIBS="-L${with_lz4_libdir} $LZ4_LIBS"
  else
    test -z "${with_lz4_libdir}" || LZ4_LIBS="-L${with_lz4_libdir} -R${with_lz4_libdir} $LZ4_LIBS"
  fi
  liblz4_LIBS="${LZ4_LIBS}"
fi
AC_SUBST([liblz4_LIBS])

if test "x${have_liblzma}" = "xyes"; then
  AC_DEFINE([HAVE_LIBLZMA], [1], [Define to 1 if liblzma is enabled.])
  liblzma_LIBS="-llzma"
  test -z "${with_liblzma_libdir}" ||
    liblzma_LIBS="-L${with_liblzma_libdir} $liblzma_LIBS"
  test -z "${with_liblzma_incdir}" ||
    liblzma_CFLAGS="-I${with_liblzma_incdir}"
  AC_SUBST([liblzma_LIBS])
  AC_SUBST([liblzma_CFLAGS])
fi

AC_CONFIG_FILES([Makefile
		 man/Makefile
		 lib/Makefile
		 mkfs/Makefile
		 dump/Makefile
		 fuse/Makefile
		 fsck/Makefile])
AC_OUTPUT
