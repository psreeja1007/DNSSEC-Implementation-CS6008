#!/bin/bash
set -e
# Client A — REFUSES cleartext (strict DoT). Reaches the resolver by name only.
ip route add 172.16.2.0/24 via 172.16.1.2 2>/dev/null || true

# Wait for the resolver to publish the CA, then install it into the system
# trust store (no -k / insecure bypass anywhere).
i=0
until [ -s /pki/ca.pem ]; do
    sleep 1
    i=$((i + 1))
    if [ "$i" -ge 120 ]; then
        echo "[client A/strict] timed out waiting for /pki/ca.pem" >&2
        exit 1
    fi
done
cp /pki/ca.pem /usr/local/share/ca-certificates/cs6008-ca.crt
update-ca-certificates >/dev/null

# Do NOT point /etc/resolv.conf at anything: this client resolves example.com
# only through resolve.sh over the encrypted transport, by name.
echo "nameserver 127.0.0.1" > /etc/resolv.conf   # inert; forces explicit use of resolve.sh

echo "[client A/strict] CA installed; reach resolver by name resolver.cs6008.local"
echo "[client A/strict] use: POSTURE=strict /usr/local/bin/resolve.sh example.com"
exec sleep infinity
