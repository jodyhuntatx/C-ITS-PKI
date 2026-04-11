FROM ubuntu:24.04

# install utilities
RUN apt update && apt install -y --no-install-recommends \
    vim \
    ssh \
    curl \
    wget \
    unzip \
    build-essential \
    cmake \
    git \
    mosquitto

RUN apt update && apt install -y --no-install-recommends \
    libboost-date-time-dev \
    libmosquittopp-dev \
    libboost-program-options-dev \
    libboost-system-dev \
    libasio-dev \
    libtinyxml2-dev \
    libcrypto++-dev

RUN apt update && apt install -y --no-install-recommends \
    libgeographiclib-dev \
    libgps-dev \
    libssl-dev \
    libnl-3-dev \
    libnl-genl-3-dev \
    zlib1g-dev \
    libcurl4-openssl-dev

RUN apt update && apt install -y --no-install-recommends \
    ca-certificates \
    file \
    doxygen \
    && rm -rf /var/lib/apt/lists/*