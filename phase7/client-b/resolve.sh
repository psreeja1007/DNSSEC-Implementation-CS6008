#!/bin/bash
# resolve.sh — query example.com over the encrypted last mile.
#
#   POSTURE=strict      DoT only. If the encrypted transport fails for ANY
#                       reason (tampered stream, bad cert, blocked port), FAIL.
#                       Never falls back to cleartext.
#   POSTURE=permissive  Try DoT; on ANY failure, fall back to cleartext Do53.
#
# Both validate the resolver cert against the lab CA and the hostname, and
# reach the resolver strictly BY NAME (resolver.cs6008.local).
set -u
NAME="${1:-example.com}"
SERVER="resolver.cs6008.local"
CA="/pki/ca.pem"
POSTURE="${POSTURE:-strict}"
TRANSPORT="${TRANSPORT:-dot}"   # dot | doh

dot_query() {
    kdig +timeout=4 +tls +tls-ca="$CA" +tls-hostname="$SERVER" \
         @"$SERVER" "$NAME" +dnssec +noall +answer +comments
}
doh_query() {
    kdig +timeout=4 +https +tls-ca="$CA" +tls-hostname="$SERVER" \
         @"$SERVER" "$NAME" +dnssec +noall +answer +comments
}
cleartext_query() {
    dig +timeout=4 @"$SERVER" "$NAME" +noall +answer +comments
}

echo "== posture=$POSTURE transport=$TRANSPORT name=$NAME =="
if [ "$TRANSPORT" = "doh" ]; then OUT=$(doh_query 2>&1); else OUT=$(dot_query 2>&1); fi
RC=$?
echo "$OUT"

if [ $RC -eq 0 ] && echo "$OUT" | grep -q "IN[[:space:]]*A"; then
    echo "[result] encrypted transport SUCCEEDED"
    exit 0
fi

echo "[result] encrypted transport FAILED (rc=$RC)"
if [ "$POSTURE" = "permissive" ]; then
    echo "[result] POSTURE=permissive -> falling back to CLEARTEXT Do53"
    cleartext_query
    exit $?
else
    echo "[result] POSTURE=strict -> refusing cleartext; no answer"
    exit 1
fi
