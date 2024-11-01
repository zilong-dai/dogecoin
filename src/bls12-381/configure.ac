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

AM_INIT_AUTOMAKE([1.11.2 foreign subdir-objects])


AC_PROG_CXX
AM_PROG_AR

LT_INIT([win32-dll])


CXXFLAGS="-O3 -flto -I include"

AC_SUBST(CXX)
AC_SUBST(CXXFLAGS)

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
