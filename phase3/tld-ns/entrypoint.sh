#!/bin/bash
set -e
mkdir -p /run/named /var/cache/bind

ip route add 172.16.2.0/24 via 172.16.3.3 2>/dev/null || true

echo "[tld-ns] routes:"
ip route

ZONEDIR=/etc/bind/zones
ZONE=com
cd "$ZONEDIR"

rm -f /pki/com.ds 

# --- Wait for domain-ns to publish its DS record (bounded wait) ---
echo "[tld-ns] waiting for /pki/example.com.ds ..."
i=0
until [ -s /pki/example.com.ds ]; do
    sleep 1
    i=$((i + 1))
    if [ "$i" -ge 120 ]; then
        echo "[tld-ns] WARNING: timed out waiting for example.com.ds" >&2
        break
    fi
done

# --- Insert the child's DS into our zone, once ---
if [ -s /pki/example.com.ds ] && ! grep -q "IN DS" "${ZONE}.zone"; then
    { echo ""; cat /pki/example.com.ds; } >> "${ZONE}.zone"
    echo "[tld-ns] inserted example.com DS into ${ZONE}.zone"
fi

# --- DNSSEC: generate KSK/ZSK once for com. ---
if ! ls "K${ZONE}.+013+"*.key >/dev/null 2>&1; then
    echo "[tld-ns] generating KSK/ZSK for ${ZONE}"
    dnssec-keygen -a ECDSAP256SHA256 -f KSK -K "$ZONEDIR" -n ZONE "${ZONE}." >/dev/null
    dnssec-keygen -a ECDSAP256SHA256 -K "$ZONEDIR" -n ZONE "${ZONE}." >/dev/null
fi

echo "[tld-ns] signing ${ZONE}"
dnssec-signzone -S -K "$ZONEDIR" -o "${ZONE}" "${ZONE}.zone" >/dev/null

# --- Publish our DS record so root-ns can pull it into the root zone ---
KSKFILE=$(grep -l 'DNSKEY 257' "K${ZONE}.+013+"*.key | head -n1)
dnssec-dsfromkey -2 "${KSKFILE%.key}" > /pki/com.ds
echo "[tld-ns] wrote DS record to /pki/com.ds:"
cat /pki/com.ds

exec /usr/sbin/named -g -c /etc/bind/named.conf
