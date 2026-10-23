FROM ubuntu:25.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bind9 bind9utils bind9-dnsutils dnsutils iproute2 iputils-ping openssl && \
    rm -rf /var/lib/apt/lists/*

RUN rndc-confgen -a
COPY named.conf /etc/bind/named.conf
COPY rndc.conf /etc/bind/rndc.conf
COPY root.hints /etc/bind/root.hints
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
