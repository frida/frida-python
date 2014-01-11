AC_INIT([frida-python], [1.0.0])
AC_CONFIG_SRCDIR([src/_frida.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE([-Wall -Werror no-dist-gzip dist-bzip2 foreign])

# Enable silent rules if available
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AM_PROG_AR
AC_PROG_INSTALL
LT_INIT

if echo $CC | grep -q "gcc"; then
  CFLAGS="$CFLAGS -fno-strict-aliasing"
fi

AM_PATH_PYTHON([2.6],, [AC_ERROR([Python is required])])
PYTHON_CONFIG=${PYTHON}-config
PYTHON_PREFIX=$($PYTHON_CONFIG --prefix)
PYTHON_EXEC_PREFIX=$($PYTHON_CONFIG --exec-prefix)
PYTHON_ABIFLAGS=$($PYTHON -c 'import sys; print(getattr(sys, "abiflags", ""))')
PYTHON_CFLAGS=$($PYTHON_CONFIG --cflags)
PYTHON_LDFLAGS=$($PYTHON_CONFIG --ldflags)
PYTHON_LIBS=$($PYTHON_CONFIG --libs)

AC_SUBST(PYTHON_CFLAGS)
AC_SUBST(PYTHON_LDFLAGS)
AC_SUBST(PYTHON_LIBS)

PKG_CHECK_MODULES(PYFRIDA, ["frida-core-1.0"])
AC_SUBST(PYFRIDA_CFLAGS)
AC_SUBST(PYFRIDA_LDFLAGS)
AC_SUBST(PYFRIDA_LIBS)

AC_CONFIG_FILES([
  Makefile
  src/Makefile
  src/frida/Makefile
])
AC_OUTPUT
