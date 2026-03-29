#!/bin/bash

set -a
source ./local.env

echo "This will delete all existing build artifacts to start a clean build."
while true; do
  read -p "Continue [Y/n]? " yn
  case $yn in
      [Yy]* ) echo "Continuing..."; break;;
      [Nn]* ) echo "Exiting..."; exit;;
      * ) echo "Invalid response, please enter Y or N.";;
  esac
done

cd $VHOME/vanetza-build
rm -rf CMake* cmake* CACHEDIR.TAG Makefile bin lib tools vanetza 
#$BOOST_BUILD_DIR $BOOST_INSTALL_DIR
