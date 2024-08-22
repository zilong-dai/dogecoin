ACLOCAL_AMFLAGS = -I build-aux/m4

AM_CXXFLAGS = -std=c++17 -fpic -O2
AM_CPPFLAGS = -std=c++17 -fpic -O2

AM_CFLAGS = --fpic -O2

lib_LTLIBRARIES = libbls.la
libbls_la_SOURCES = src/groth16.cpp src/arithmetic.cpp src/fp.cpp src/g.cpp src/pairing.cpp src/scalar.cpp src/utils.cpp

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libbls.pc
