#!/bin/bash
set -e
# Client B — PERMITS cleartext fallback (opportunistic). Same CA + name.
ip route add 172.16.2.0/24 via 172.16.1.2 2>/dev/null || true

i=0
until [ -s /pki/ca.pem ]; do
    sleep 1
    i=$((i + 1))
    if [ "$i" -ge 120 ]; then
        echo "[client B/permissive] timed out waiting for /pki/ca.pem" >&2
        exit 1
    fi
done
cp /pki/ca.pem /usr/local/share/ca-certificates/cs6008-ca.crt
update-ca-certificates >/dev/null

echo "nameserver 127.0.0.1" > /etc/resolv.conf   # inert

echo "[client B/permissive] CA installed; reach resolver by name resolver.cs6008.local"
echo "[client B/permissive] use: POSTURE=permissive /usr/local/bin/resolve.sh example.com"
exec sleep infinity
