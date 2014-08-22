#
# $Id: configure.ac,v 0d6e5d383a92 2010/08/27 04:28:27 Hirochika $
#
# Copyright (c) 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
# Authors:
#      Hirochika Asai  <asai@scyphus.co.jp>
#

AC_PREREQ(2.59)
AC_INIT([ribtools], [current], [bug@scyphus.co.jp])
AC_CONFIG_SRCDIR([gao/infer-asrel-gao.c])
AC_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE
AC_SUBST(SUBDIRS)

# arguments
AC_ARG_ENABLE(debug,
  [  --enable-debug    Turn on debugging [default no]],
  [case "${enableval}" in
    yes) debug=yes; AC_MSG_RESULT(Checking for debug... yes); AC_DEFINE(DEBUG, 1, debugging option) ;;
    no)  debug=no;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
  esac],[debug=no])
AM_CONDITIONAL(DEBUG, test x$debug = xtrue)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LN_S
AC_PROG_RANLIB
AC_PROG_INSTALL

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h stddef.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([strcasecmp strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
