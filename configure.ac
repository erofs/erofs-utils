#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])

m4_define([erofs_utils_version], m4_esyscmd([sed -n '1p' VERSION | tr -d '\n']))
m4_define([erofs_utils_date], m4_esyscmd([sed -n '2p' VERSION | tr -d '\n']))

AC_INIT([erofs-utils], [erofs_utils_version], [linux-erofs@lists.ozlabs.org])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Checks for programs.
AM_PROG_AR
AC_PROG_CC
AC_PROG_INSTALL

LT_INIT

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

AC_ARG_ENABLE(lz4,
   [AS_HELP_STRING([--disable-lz4], [disable LZ4 compression support @<:@default=enabled@:>@])],
   [enable_lz4="$enableval"], [enable_lz4="yes"])

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

# Checks for header files.
AC_CHECK_HEADERS(m4_flatten([
	dirent.h
	fcntl.h
	inttypes.h
	linux/types.h
	limits.h
	stddef.h
	stdint.h
	stdlib.h
	string.h
	sys/stat.h
	sys/time.h
	unistd.h
]))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
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

# Checks for library functions.
AC_CHECK_FUNCS([gettimeofday memset realpath strdup strerror strrchr strtoull])

# Configure lz4
test -z $LZ4_LIBS && LZ4_LIBS='-llz4'

if test "x$enable_lz4" = "xyes"; then
  test -z "${with_lz4_incdir}" || LZ4_CFLAGS="-I$with_lz4_incdir $LZ4_CFLAGS"
  test -z "${with_lz4_libdir}" || LZ4_LIBS="-L$with_lz4_libdir $LZ4_LIBS"

  saved_CPPFLAGS=${CPPFLAGS}
  CPPFLAGS="${LZ4_CFLAGS} ${CFLAGS}"

  AC_CHECK_HEADERS([lz4.h],[have_lz4h="yes"], [])

  if test "x${have_lz4h}" = "xyes" ; then
    saved_LDFLAGS=${LDFLAGS}
    LDFLAGS="-L$with_lz4_libdir ${LDFLAGS}"
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

    if test "x${have_lz4}" = "xyes"; then
      AC_DEFINE([LZ4_ENABLED], [1], [Define to 1 if lz4 is enabled.])

      if test "x${have_lz4hc}" = "xyes"; then
        AC_DEFINE([LZ4HC_ENABLED], [1], [Define to 1 if lz4hc is enabled.])
      fi

      if test "x${lz4_force_static}" = "xyes"; then
        LDFLAGS="-all-static ${LDFLAGS}"
      else
	test -z "${with_lz4_libdir}" || LZ4_LIBS="-R ${with_lz4_libdir} $LZ4_LIBS"
      fi
      LIBS="$LZ4_LIBS $LIBS"
    fi
  fi
  CFLAGS=${saved_CPPFLAGS}
fi

AM_CONDITIONAL([ENABLE_LZ4], [test "x${have_lz4}" = "xyes"])
AM_CONDITIONAL([ENABLE_LZ4HC], [test "x${have_lz4hc}" = "xyes"])

AC_CONFIG_FILES([Makefile
		 lib/Makefile
		 mkfs/Makefile])
AC_OUTPUT

