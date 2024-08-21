ACLOCAL_AMFLAGS = -I build-aux/m4

AM_CXXFLAGS = -std=c++17 -fpic -g3
AM_CPPFLAGS = -std=c++17 -fpic -g3 

AM_CFLAGS = --fpic -g3

lib_LTLIBRARIES = libmcl.la

#include_HEADERS = include/bls12-381/bls12-381.hpp include/bls12-381/arithmetic.hpp include/bls12-381/fp.hpp include/bls12-381/g.hpp include/bls12-381/pairing.hpp include/bls12-381/scalar.hpp include/bls12-381/utils.hpp include/groth16/groth16.hpp include/groth16/proof.hpp include/groth16/serialize.hpp include/groth16/vk.hpp include/polyfills/optional.hpp include/polyfills/span.hpp 

libmcl_la_SOURCES = src/groth16.cpp src/arithmetic.cpp src/fp.cpp src/g.cpp src/pairing.cpp src/scalar.cpp src/utils.cpp

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmcl.pc

