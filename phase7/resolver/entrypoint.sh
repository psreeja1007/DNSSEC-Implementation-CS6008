#!/bin/bash
set -e
mkdir -p /run/named /var/cache/bind /etc/bind/certs

ip route add 172.16.3.0/24 via 172.16.2.3 2>/dev/null || true
ip route add 172.16.1.0/24 via 172.16.2.2 2>/dev/null || true

rm -f /pki/root-anchor.conf

echo "[resolver] routes:"; ip route

# ------------------------------------------------------------------
# (A) Private CA + resolver TLS certificate for the encrypted last mile.
#     CA key stays on the resolver host; only the CA cert (ca.pem) and the
#     server cert (public) are published to /pki for the clients to trust.
#     SAN is DNS:resolver.cs6008.local only -- no IP SAN -- so the client
#     must reach the resolver BY NAME.
# ------------------------------------------------------------------
HOSTNAME_TLS="resolver.cs6008.local"
CADIR=/etc/bind/ca
CERTDIR=/etc/bind/certs
mkdir -p "$CADIR"

if [ ! -s "$CERTDIR/resolver.cert.pem" ]; then
    echo "[resolver] generating private CA + server certificate for ${HOSTNAME_TLS}"
    openssl ecparam -name prime256v1 -genkey -noout -out "$CADIR/ca.key"
    openssl req -x509 -new -key "$CADIR/ca.key" -sha256 -days 3650 \
        -subj "/CN=CS6008 Lab Root CA" -out "$CADIR/ca.pem"

    openssl ecparam -name prime256v1 -genkey -noout -out "$CERTDIR/resolver.key"
    openssl req -new -key "$CERTDIR/resolver.key" -subj "/CN=${HOSTNAME_TLS}" \
        -out "$CADIR/resolver.csr"

    cat > "$CADIR/ext.cnf" <<EOF
subjectAltName = DNS:${HOSTNAME_TLS}
extendedKeyUsage = serverAuth
EOF
    openssl x509 -req -in "$CADIR/resolver.csr" -CA "$CADIR/ca.pem" -CAkey "$CADIR/ca.key" \
        -CAcreateserial -days 825 -sha256 -extfile "$CADIR/ext.cnf" \
        -out "$CERTDIR/resolver.cert.pem"
fi

# Publish the trust material the clients need (public only).
cp "$CADIR/ca.pem" /pki/ca.pem
cp "$CERTDIR/resolver.cert.pem" /pki/resolver.cert.pem
chmod 0644 /pki/ca.pem /pki/resolver.cert.pem
echo "[resolver] published /pki/ca.pem (CA) and /pki/resolver.cert.pem"
openssl x509 -in "$CERTDIR/resolver.cert.pem" -noout -subject -ext subjectAltName

# ------------------------------------------------------------------
# (B) DNSSEC root trust anchor (unchanged from Phase 3).
# ------------------------------------------------------------------
echo "[resolver] waiting for /pki/root.key ..."
i=0
until [ -s /pki/root.key ]; do
    sleep 1; i=$((i + 1))
    [ "$i" -ge 120 ] && { echo "[resolver] WARNING: timed out waiting for root.key" >&2; break; }
done

KEYLINE=$(grep -v '^;' /pki/root.key | grep -m1 DNSKEY)
FLAGS=$(echo "$KEYLINE" | awk '{print $4}')
PROTO=$(echo "$KEYLINE" | awk '{print $5}')
ALG=$(echo "$KEYLINE" | awk '{print $6}')
KEYDATA=$(echo "$KEYLINE" | awk '{for (i=7;i<=NF;i++) printf "%s",$i}')

cat > /etc/bind/trust-anchor.conf <<EOC
trust-anchors {
    "." static-key ${FLAGS} ${PROTO} ${ALG} "${KEYDATA}";
};
EOC
cp /etc/bind/trust-anchor.conf /pki/root-anchor.conf
echo "[resolver] DNSSEC trust anchor installed; delv anchor at /pki/root-anchor.conf"

exec /usr/sbin/named -g -c /etc/bind/named.conf
