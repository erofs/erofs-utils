#!/bin/sh
# SPDX-License-Identifier: GPL-2.0+

aclocal && \
autoheader && \
autoconf && \
libtoolize && \
automake -a -c

