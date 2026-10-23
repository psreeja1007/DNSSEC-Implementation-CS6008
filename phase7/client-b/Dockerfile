FROM ubuntu:25.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        dnsutils bind9-dnsutils knot-dnsutils curl openssl ca-certificates \
        iproute2 iputils-ping tcpdump && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY resolve.sh /usr/local/bin/resolve.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/resolve.sh

ENTRYPOINT ["/entrypoint.sh"]
