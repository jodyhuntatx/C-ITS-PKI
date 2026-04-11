#!/bin/bash

# This is executed in the build container with the current directory mounted at /tool-build
set -a
source ./local.env

main() {
#  ./_reset-build.sh
#  install_deps
  cmake $VHOME \
    -Wno-dev \
    -DCMAKE_INSTALL_RPATH=\$ORIGIN/lib \
    -DCMAKE_INSTALL_PREFIX=./vanetza-dist \
    -DBoost_ROOT=/usr/lib/aarch64-linux-gnu/cmake \
    -DBoost_DEBUG=ON \
    -DOPENSSL_INCLUDE_DIR=/usr/include/openssl \
    -DOPENSSL_ROOT_DIR=/usr/lib/aarch64-linux-gnu \
    -DVANETZA_WITH_OPENSSL=ON \
    -DVANETZA_WITH_CRYPTOPP=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_SOCKTAP=OFF \
    -DBUILD_FUZZ=ON \
    -DBUILD_BENCHMARK=ON \
    -DBUILD_CERTIFY=ON

    make

  exit

  # Generate API docs w/ doxygen
  cd $VHOME
  if [ ! -f doxygen/html/index.html ]; then
    doxygen
  fi
  echo "API docs are at: $VHOME/doxygen/html/index.html"
}

#######################################
install_deps() {
  echo "Installing dependencies..."
}

#######################################
build_boost() {
  if [ ! -d ${BOOST_BUILD_DIR} ]; then
    if [ ! -f ${BOOST_TARFILE} ]; then
      echo "Downloading boost tarfile boost_${BOOST_MAJOR_VERSION}_${BOOST_MINOR_VERSION}_0.tar.gz ..."
      curl -O https://archives.boost.io/release/${BOOST_MAJOR_VERSION}.${BOOST_MINOR_VERSION}.0/source/${BOOST_TARFILE}
    fi
    echo "Untarring tarfile..."
    tar xf ${BOOST_TARFILE}
  fi
  pushd ${BOOST_BUILD_DIR}
    ./bootstrap.sh --prefix=${BOOST_INSTALL_DIR}
    ./b2
    ./b2 install
  popd
}

main "$@"