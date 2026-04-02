#!/bin/bash

if [ ! -d vanetza-nap ]; then
    git clone git@github.com:nap-it/vanetza-nap.git
fi

cd vanetza-nap

if [[ "$(docker network ls -f"name=vanetzalan0" -q)" == "" ]]; then
  docker network create vanetzalan0 --subnet 192.168.98.0/24
fi

docker-compose up -d

