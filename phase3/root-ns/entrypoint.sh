#!/bin/bash
set -e
mkdir -p /run/named /var/cache/bind

ip route add 172.16.2.0/24 via 172.16.3.3 2>/dev/null || true

echo "[root-ns] routes:"
ip route

ZONEDIR=/etc/bind/zones
cd "$ZONEDIR"

# --- Wait for tld-ns to publish its DS record (bounded wait) ---
echo "[root-ns] waiting for /pki/com.ds ..."
i=0
until [ -s /pki/com.ds ]; do
    sleep 1
    i=$((i + 1))
    if [ "$i" -ge 120 ]; then
        echo "[root-ns] WARNING: timed out waiting for com.ds" >&2
        break
    fi
done

# --- Insert the child's DS into the root zone, once ---
if [ -s /pki/com.ds ] && ! grep -q "IN DS" root.zone; then
    { echo ""; cat /pki/com.ds; } >> root.zone
    echo "[root-ns] inserted com DS into root.zone"
fi

# --- DNSSEC: generate KSK/ZSK once for the root. This is the trust point,
#     so it is self-signed -- there is no parent to hand a DS to. ---
if ! ls "K.+013+"*.key >/dev/null 2>&1; then
    echo "[root-ns] generating KSK/ZSK for the root zone"
    dnssec-keygen -a ECDSAP256SHA256 -f KSK -K "$ZONEDIR" -n ZONE "." >/dev/null
    dnssec-keygen -a ECDSAP256SHA256 -K "$ZONEDIR" -n ZONE "." >/dev/null
fi

echo "[root-ns] signing root zone"
dnssec-signzone -S -K "$ZONEDIR" -o "." root.zone >/dev/null

# --- Publish our KSK so the resolver can install it as its trust anchor ---
KSKFILE=$(grep -l 'DNSKEY 257' "K.+013+"*.key | head -n1)
cp "$KSKFILE" /pki/root.key
echo "[root-ns] published root KSK to /pki/root.key"

exec /usr/sbin/named -g -c /etc/bind/named.conf
