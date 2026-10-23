FROM ubuntu:25.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 iproute2 iputils-ping && \
    rm -rf /var/lib/apt/lists/*

COPY html /var/www/html
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /var/www/html
ENTRYPOINT ["/entrypoint.sh"]
