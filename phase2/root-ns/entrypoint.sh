#!/bin/bash
set -e
mkdir -p /run/named /var/cache/bind

# Static route: reach the resolver subnet via core-router
ip route add 172.16.2.0/24 via 172.16.3.3 2>/dev/null || true

echo "[root-ns] routes:"
ip route

exec /usr/sbin/named -g -c /etc/bind/named.conf
