FROM ubuntu:25.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bind9 bind9utils dnsutils iproute2 iputils-ping && \
    rm -rf /var/lib/apt/lists/*

COPY named.conf /etc/bind/named.conf
COPY zones/example.com.zone /etc/bind/zones/example.com.zone
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
