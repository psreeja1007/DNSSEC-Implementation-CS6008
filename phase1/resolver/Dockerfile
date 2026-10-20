FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bind9 bind9utils bind9-dnsutils dnsutils iproute2 iputils-ping && \
    rm -rf /var/lib/apt/lists/*

COPY named.conf /etc/bind/named.conf
COPY root.hints /etc/bind/root.hints
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
