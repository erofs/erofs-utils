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

# Checks for libraries.

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

AC_CONFIG_FILES([Makefile
		 lib/Makefile])
AC_OUTPUT
