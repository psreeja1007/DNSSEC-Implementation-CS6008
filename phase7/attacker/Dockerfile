FROM ubuntu:25.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    iproute2 \
    dnsutils \
    tcpdump \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY . /attacker
WORKDIR /attacker
RUN make

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
