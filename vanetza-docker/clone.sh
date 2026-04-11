#!/bin/bash
REPO=git@github.com:riebl/vanetza.git
#REPO=git@github.com:nap-it/vanetza-nap.git

if [ ! -d vanetza ]; then
    git clone $REPO
fi
echo "$REPO is cloned in the local filesystem."
