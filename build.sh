#!/bin/bash
set -e

# To build with tests, install cmocka-dev and define EXTRA_CMAKE_FLAGS as:
# EXTRA_CMAKE_FLAGS=-DUNIT_TESTING=ON
# Also make sure that gcc-8 is used when building the test suite.  If it isn't, add (e.g.) -DCMAKE_C_COMPILER=gcc-8 -DCMAKE_CXX_COMPILER=g++-8
# to EXTRA_CMAKE_FLAGS.  See example below:
# EXTRA_CMAKE_FLAGS="-DUNIT_TESTING=ON -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_C_COMPILER=gcc-8 -DCMAKE_CXX_COMPILER=g++-8"

SRCDIR=`dirname $0`
BUILDDIR="$SRCDIR/build"

# Ensure "clean-start" by removing any prior build first
rm -rf "$BUILDDIR"
mkdir -p "$BUILDDIR"

if hash cmake3 2>/dev/null; then
    # CentOS users should install cmake3 from EPEL
    CMAKE=cmake3
else
    CMAKE=cmake
fi

cd "$BUILDDIR"

CMD="$CMAKE -DCMAKE_BUILD_TYPE="Release" ${EXTRA_CMAKE_FLAGS:-} .."
echo $CMD
eval $CMD
CMD="make -j"$(nproc)
echo $CMD
eval $CMD
