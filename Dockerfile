FROM docker.io/library/ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

ARG TZ=America/New_York
ENV TZ ${TZ}

RUN apt update -y \
  && apt install -y \
    ca-certificates \
    libssl-dev \
    tzdata \
    build-essential \
    cmake \
    build-essential \
    libtool \
    autotools-dev \
    automake \
    pkg-config \
    libssl-dev \
    libzmq3-dev \
    libevent-dev \
    bsdmainutils \
    libboost-system-dev \
    libboost-filesystem-dev \
    libboost-chrono-dev \
    libboost-program-options-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libdb5.3++-dev \
    clang-15 \
  && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 1 --slave /usr/bin/clang++ clang++ /usr/bin/clang++-15

RUN ln -fs /usr/share/zoneinfo/$TZ /etc/localtime
RUN dpkg-reconfigure --frontend noninteractive tzdata

WORKDIR /dogecoin

COPY . /dogecoin

RUN ./autogen.sh \
  && ./configure \
  && make -j$(nproc) install

RUN echo '#!/bin/bash\n/usr/local/bin/dogecoind $@' > /dogecoin/.entrypoint.sh
RUN chmod u+x /dogecoin/.entrypoint.sh

ENTRYPOINT ["/dogecoin/.entrypoint.sh"]