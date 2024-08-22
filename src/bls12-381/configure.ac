AC_PREREQ([2.60])

define(_PKG_VERSION_MAJOR, 0)
define(_PKG_VERSION_MINOR, 1)
define(_PKG_VERSION_BUILD, 0)
define(_PKG_VERSION_IS_RELEASE, false)

define(_LIB_VERSION_CURRENT, 0)
define(_LIB_VERSION_REVISION, 0)
define(_LIB_VERSION_AGE, 0)
AC_INIT([libbls], m4_join([.], _PKG_VERSION_MAJOR, _PKG_VERSION_MINOR, _PKG_VERSION_BUILD)m4_if(_PKG_VERSION_IS_RELEASE, [true], [], [-pre]), [https://github.com/QEDProtocol/bls12-381/issues], [libbls], [https://github.com/QEDProtocol/bls12-381])

AC_SUBST(LIB_VERSION_CURRENT, _LIB_VERSION_CURRENT)
AC_SUBST(LIB_VERSION_REVISION, _LIB_VERSION_REVISION)
AC_SUBST(LIB_VERSION_AGE, _LIB_VERSION_AGE)
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])
AC_CANONICAL_HOST
AH_TOP([#ifndef LIBMCL_CONFIG_H])
AH_TOP([#define LIBMCL_CONFIG_H])
AH_BOTTOM([#endif /*LIBMCL_CONFIG_H*/])

AM_INIT_AUTOMAKE([1.11.2 foreign subdir-objects])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CXX
AC_PROG_CC
AM_PROG_AR

LT_INIT([win32-dll])

AC_CANONICAL_HOST
case "$host_os" in
    *mingw64*)
        CXXFLAGS="$CXXFLAGS -D__USE_MINGW_ANSI_STDIO=1"
        ;;
    *cygwin*)
        ;;
    *darwin*)
        AC_DEFINE([DARWIN], [1], [Define if on Darwin/Mac OS X])
        ;;
    *openbsd*)
        CXXFLAGS="$CXXFLAGS -I/usr/local/include"
        LDFLAGS="$LDFLAGS -L/usr/local/lib"
        ;;
    *freebsd*)
        CXXFLAGS="$CXXFLAGS -I/usr/local/include"
        LDFLAGS="$LDFLAGS -L/usr/local/lib"
        ;;
    *linux*)
        CXXFLAGS="$CXXFLAGS -I/usr/local/include"
        LDFLAGS="$LDFLAGS -L/usr/local/lib"
        ;;
esac


CXXFLAGS_WARN="-Wall -Wextra -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings -Wfloat-equal -Wpointer-arith -Wundef"
CXXFLAGS="$CXXFLAGS $CXXFLAGS_WARN -I include -I src"

AC_SUBST(CXXFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(CXX)
AC_SUBST(CC)

AC_CONFIG_FILES([Makefile libbls.pc])

AC_OUTPUT

echo
echo "  target os     = $TARGET_OS"
echo "  build os      = $BUILD_OS"
echo
echo "  CC            = $CC"
echo "  CPPFLAGS      = $CPPFLAGS"
echo "  CXX           = $CXX"
echo "  CXXFLAGS      = $CXXFLAGS"
echo "  LDFLAGS       = $LDFLAGS"
echo
