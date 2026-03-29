#!/bin/bash

set -a
source ./local.env

main() {
  setup
  cd $VHOME/vanetza-build
  install_deps
  cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=$VHOME/cmake/Toolchain-Darwin.cmake \
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
  # Clone repo if not there
  if [ ! -d "$VHOME" ]; then
    pushd $VROOT
      git clone git@github.com:riebl/vanetza.git
    popd
  fi

  echo "Copying Darwin-specific CMakeList.txt to $VHOME..."
  echo "Differences:"
  sdiff -s $VHOME/CMakeLists.txt ./CMakeLists.txt
  cp ./CMakeLists.txt $VHOME
  echo "Copying Darwin-specific Toolchain file to $VHOME/cmake..."
  cp ./Toolchain-Darwin.cmake $VHOME/cmake

  mkdir -p $VHOME/vanetza-build
}

#######################################
install_deps() {
  echo "Installing MacOS CLI tools..."
  xcode-select --install

  if [[ "$(which brew)" == "" ]]; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  fi

  if [[ "$(which gcc)" == "" ]]; then
    echo "Installing gcc/g++ ...."
    brew install gcc
  fi

  if [[ "$(which doxygen)" == "" ]]; then
    echo "Installing doxygen & graphviz ...."
    brew install doxygen graphviz
  fi

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
  cd ${BOOST_BUILD_DIR}
  ./bootstrap.sh --prefix=${BOOST_INSTALL_DIR}
  ./b2
  ./b2 install
}

main "$@"
