#!/bin/bash

set -a
source ./local.env

main() {
  setup
  mkdir -p $VHOME/vanetza-build
  cd $VHOME/vanetza-build
  install_deps
  cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=$VHOME/cmake/Toolchain-ARM64.cmake \
    -DCMAKE_FIND_ROOT_PATH=$VHOME/vanetza-deps \
    -DCMAKE_INSTALL_RPATH=\$ORIGIN/../lib \
    -DCMAKE_INSTALL_PREFIX=$VHOME/vanetza-dist \
    -DBOOST_ROOT=$VHOME/boost \
    -DBoost_DEBUG=OFF \
    -DOPENSSL_CRYPTO_LIBRARY=$OPENSSL_ROOT_DIR/lib/libcrypto.dylib \
    -DOPENSSL_INCLUDE_DIR=$OPENSSL_ROOT_DIR/include \
    -DVANETZA_WITH_OPENSSL=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_SOCKTAP=OFF \
    -DBUILD_FUZZ=ON \
    -DBUILD_BENCHMARK=ON \
    -DBUILD_CERTIFY=ON
  make

  # Generate API docs w/ doxygen
  cd $VHOME
  if [ ! -f doxygen/html/index.html ]; then
    doxygen
  fi
  echo "API docs are at: $VHOME/doxygen/html/index.html"
}

#######################################
setup() {
  echo "Running setup...."
}

#######################################
install_deps() {
  if [ ! -d ${BOOST_INSTALL_DIR} ]; then
    echo "Building Boost lib..."
    build_boost
  fi
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
