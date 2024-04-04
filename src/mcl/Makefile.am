BIT=64
ACLOCAL_AMFLAGS = -I build-aux/m4

AM_CXXFLAGS = -std=c++03 -I$(top_srcdir)/include -I$(top_srcdir)/src $(MCL_CFLAGS)

lib_LTLIBRARIES = libmcl.la
include_HEADERS = include/mcl/bn.h include/mcl/bn_c384_256.h include/mcl/config.h include/mcl/curve_type.h include/mcl/fp.h include/mcl/bint.hpp src/bint_impl.hpp include/cybozu/bit_operation.hpp include/cybozu/exception.hpp include/cybozu/hash.hpp include/cybozu/itoa.hpp include/cybozu/mutex.hpp include/cybozu/random_generator.hpp include/cybozu/serializer.hpp include/cybozu/stream.hpp 
nodist_libmcl_la_OBJECTS = src/libmcl_la-fp.lo \
	src/libmcl_la-bn_c384_256.lo bint.lo base.lo
nodist_libmcl_la_SOURCES = src/fp.cpp src/bn_c384_256.cpp
# $(OBJ_DIR)/bint.lo $(OBJ_DIR)/base.lo
#libmcl_la_LIBADD = -lgmp -lgmpxx
libmcl_la_LDFLAGS = -no-undefined -version-info $(LIB_VERSION_CURRENT):$(LIB_VERSION_REVISION):$(LIB_VERSION_AGE)
libmcl_la_CPPFLAGS = -I$(top_srcdir)/include $(MCL_CFLAGS)
libmcl_la_LIBADD = $(MCL_LIBS)

mclincludedir = $(includedir)/mcl
mclinclude_HEADERS = $(mcl_headers)


TESTS =
#if USE_TESTS
#TESTS += test/fp_test test/bn_c384_256_test
#check_PROGRAMS = $(TESTS) 
#test_fp_test_SOURCES = test/fp_test.cpp
#test_fp_test_LDADD = libmcl.la
#test_bn_c384_256_test_SOURCES = test/bn_c384_256_test.cpp  
#test_bn_c384_256_test_LDADD = libmcl.la
#endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmcl.pc

EXTRA_DIST = CHANGELOG.md COPYING readme.md



bint.lo: src/bint$(BIT).ll
	$(LIBTOOL) --mode=compile $(CXX) -c $< -o $@ $(CFLAGS)

base.lo: src/base$(BIT).ll
	$(LIBTOOL) --mode=compile $(CXX) -c $< -o $@ $(CFLAGS)