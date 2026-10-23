#!/bin/bash
set -e

# Client B — a LOCALLY VALIDATING client. It still asks the lab resolver, but
# it validates the DNSSEC chain itself (delv) against the root KSK as its own
# trust anchor (/pki/root-anchor.conf, published read-only by the resolver).
# Because it checks signatures locally, a last-mile forgery that rewrites only
# the A record (leaving the RRSIG stale) is caught here.

ip route add 172.16.2.0/24 via 172.16.1.2 2>/dev/null || true

echo "nameserver 172.16.2.10" > /etc/resolv.conf

echo "[client-b] routes:"
ip route
echo "[client-b] resolv.conf:"
cat /etc/resolv.conf

exec sleep infinity
