#!/bin/sh
# SPDX-License-Identifier: GPL-2.0+

aclocal && \
autoheader && \
autoconf && \
case `uname` in Darwin*) glibtoolize --copy ;; \
  *) libtoolize --copy ;; esac && \
automake -a -c
