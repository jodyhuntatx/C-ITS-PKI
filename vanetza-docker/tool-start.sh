#!/bin/bash

# This is executed on the host OS

docker stop tools && docker rm tools
docker build -t tools .
docker run -d \
  --name tools \
  --volume $(pwd)/tool-build:/tool-build \
  --volume $(pwd)/vanetza:/vanetza \
  tools \
  sleep infinity
docker exec -it tools bash
