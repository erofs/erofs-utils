#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([mkfs.erofs], [0.0.1], [bluce.liguifu@huawei.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_SRCDIR([mkfs/mkfs_main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

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

# checks system architecture firtly for enable support larg file
ARCH_BIT=`getconf LONG_BIT`
AM_CONDITIONAL([SUPPORT_LARG_FILE_AT_BIT32],[test x$ARCH_BIT = x32])

# Checks for libraries.
# Ask user for LZ4 library path if needed.

AC_ARG_WITH(lz4_include,
   [  --with-lz4-include=DIR  LZ4 include directory ],
   EROFS_UTILS_PARSE_DIRECTORY(["$withval"],[withval])
   CPPFLAGS="$CPPFLAGS -I$withval")

AC_ARG_WITH(lz4_lib,
   [  --with-lz4-lib=DIR      LZ4 lib directory ], [
   EROFS_UTILS_PARSE_DIRECTORY(["$withval"],[withval])
   LDFLAGS="$LDFLAGS -L$withval"
   lz4_lib_path="$withval"
  ])

AC_ARG_WITH(lz4,
   [  --with-lz4=DIR          LZ4 install directory, e.g. /usr/local or /usr ], [
   EROFS_UTILS_PARSE_DIRECTORY(["$withval"],[withval])
   if test -z "$with_gmp_lib" && test -z "$with_gmp_include" ; then
      CPPFLAGS="$CPPFLAGS -I$withval/include"
      LDFLAGS="$LDFLAGS -L$withval/lib"
      lz4_lib_path="$withval/lib"
   else
      AC_MSG_FAILURE([Do not use --with-lz4 and --with-lz4-include/--with-lz4-lib options simultaneously.])
   fi
  ])

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

# Configure lz4.
have_lz4="1"
AC_CHECK_HEADERS([lz4.h], , [have_lz4="0"])
AC_CHECK_LIB(lz4, LZ4_versionNumber, [LIBS="-Wl,-Bstatic,-llz4,-Bdynamic $LIBS"] , [have_lz4="0"])
if test "x${have_lz4}" = "x0" ; then
  AC_MSG_ERROR([Cannot build without lz4])
fi

AC_CONFIG_FILES([Makefile
		 mkfs/Makefile])
AC_OUTPUT
