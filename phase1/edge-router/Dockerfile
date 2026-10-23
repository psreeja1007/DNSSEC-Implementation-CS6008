FROM ubuntu:25.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 iputils-ping tcpdump && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
