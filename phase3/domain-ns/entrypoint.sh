#!/bin/bash
set -e
mkdir -p /run/named /var/cache/bind

# Static route: reach the resolver subnet via core-router
ip route add 172.16.2.0/24 via 172.16.3.3 2>/dev/null || true

echo "[domain-ns] routes:"
ip route

ZONEDIR=/etc/bind/zones
ZONE=example.com
cd "$ZONEDIR"

rm -f /pki/example.com.ds 

# --- DNSSEC: generate KSK/ZSK once; keys live in this container's own
#     writable layer, never on the host, never committed. ---
if ! ls "K${ZONE}.+013+"*.key >/dev/null 2>&1; then
    echo "[domain-ns] generating KSK/ZSK for ${ZONE}"
    dnssec-keygen -a ECDSAP256SHA256 -f KSK -K "$ZONEDIR" -n ZONE "${ZONE}." >/dev/null
    dnssec-keygen -a ECDSAP256SHA256 -K "$ZONEDIR" -n ZONE "${ZONE}." >/dev/null
fi

echo "[domain-ns] signing ${ZONE}"
dnssec-signzone -S -K "$ZONEDIR" -o "${ZONE}" "${ZONE}.zone" >/dev/null

# --- Publish our DS record so tld-ns can pull it into the com. zone ---
KSKFILE=$(grep -l 'DNSKEY 257' "K${ZONE}.+013+"*.key | head -n1)
dnssec-dsfromkey -2 "${KSKFILE%.key}" > /pki/example.com.ds
echo "[domain-ns] wrote DS record to /pki/example.com.ds:"
cat /pki/example.com.ds

exec /usr/sbin/named -g -c /etc/bind/named.conf
