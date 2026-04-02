#!/bin/sh
# SPDX-License-Identifier: MIT

aclocal && \
autoheader && \
autoconf && \
case `uname` in Darwin*) glibtoolize --copy ;; \
  *) libtoolize --copy ;; esac && \
automake -a -c
