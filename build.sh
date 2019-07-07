#!/bin/bash
set -e

# To build with tests, install cmocka-dev and define EXTRA_CMAKE_FLAGS as:
# EXTRA_CMAKE_FLAGS=-DUNIT_TESTING=ON

SRCDIR=`dirname $0`
BUILDDIR="$SRCDIR/build"

mkdir -p "$BUILDDIR"

if hash cmake3 2>/dev/null; then
    # CentOS users should install cmake3 from EPEL
    CMAKE=cmake3
else
    CMAKE=cmake
fi

cd "$BUILDDIR"

$CMAKE -DCMAKE_BUILD_TYPE="Release" ${EXTRA_CMAKE_FLAGS:-} ..
make -j8
