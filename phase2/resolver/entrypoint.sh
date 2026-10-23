#!/bin/bash
set -e
mkdir -p /run/named /var/cache/bind

ip route add 172.16.3.0/24 via 172.16.2.3 2>/dev/null || true
ip route add 172.16.1.0/24 via 172.16.2.2 2>/dev/null || true

echo "[resolver] routes:"
ip route

exec /usr/sbin/named -g -c /etc/bind/named.conf
