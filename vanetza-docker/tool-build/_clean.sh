#!/bin/bash

echo "This will delete ALL existing build artifacts for repo commits."
while true; do
  read -p "Continue [Y/n]? " yn
  case $yn in
      [Yy]* ) echo "Continuing..."; break;;
      [Nn]* ) echo "Exiting..."; exit;;
      * ) echo "Invalid response, please enter Y or N.";;
  esac
done

rm -rf CMake* cmake* Vanetza*.cmake CACHEDIR.TAG Makefile bin lib tools vanetza boost* vanetza-nap
