#!/bin/bash
set -e
mkdir -p /run/named /var/cache/bind

ip route add 172.16.3.0/24 via 172.16.2.3 2>/dev/null || true
ip route add 172.16.1.0/24 via 172.16.2.2 2>/dev/null || true

echo "[resolver] routes:"
ip route

# --- Wait for root-ns to publish its KSK (bounded wait) ---
echo "[resolver] waiting for /pki/root.key ..."
i=0
until [ -s /pki/root.key ]; do
    sleep 1
    i=$((i + 1))
    if [ "$i" -ge 120 ]; then
        echo "[resolver] WARNING: timed out waiting for root.key" >&2
        break
    fi
done

# --- Turn the root KSK's .key file into a BIND 9.20 trust-anchors clause.
#     A dnssec-keygen .key file line looks like:
#       .                       IN DNSKEY 257 3 13 <base64 key data>
KEYLINE=$(grep -v '^;' /pki/root.key | grep -m1 DNSKEY)
FLAGS=$(echo "$KEYLINE" | awk '{print $4}')
PROTO=$(echo "$KEYLINE" | awk '{print $5}')
ALG=$(echo "$KEYLINE" | awk '{print $6}')
KEYDATA=$(echo "$KEYLINE" | awk '{for (i = 7; i <= NF; i++) printf "%s", $i}')

cat > /etc/bind/trust-anchor.conf << EOC
trust-anchors {
    "." static-key ${FLAGS} ${PROTO} ${ALG} "${KEYDATA}";
};
EOC

cat > /pki/root-anchor.conf << EOC
trust-anchors {
    "." static-key ${FLAGS} ${PROTO} ${ALG} "${KEYDATA}";
};
EOC

echo "[resolver] trust anchor installed:"
cat /etc/bind/trust-anchor.conf
echo "[resolver] delv trust anchor published to /pki/root-anchor.conf"

exec /usr/sbin/named -g -c /etc/bind/named.conf
