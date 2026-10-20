#!/bin/bash
set -e

ip route add 172.16.2.0/24 via 172.16.1.2 2>/dev/null || true

# Point this host's resolver at our lab resolver, not any Docker-provided DNS
echo "nameserver 172.16.2.10" > /etc/resolv.conf

echo "[client] routes:"
ip route
echo "[client] resolv.conf:"
cat /etc/resolv.conf

# Keep the container alive for interactive use (docker exec)
exec sleep infinity
