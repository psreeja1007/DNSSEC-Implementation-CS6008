#!/bin/bash
set -e

# Edge-router forwards client subnet <-> resolver subnet (no NAT). In Phase 6
# it also performs the LAST-MILE diversion: resolver -> client replies are
# steered through the attacker (172.16.1.100) on the client subnet.

echo "[edge-router] interfaces:"
ip -4 addr show

ATTACKER_IP="${ATTACKER_IP:-172.16.1.100}"
CLIENTS="${DIVERT_CLIENTS:-172.16.1.10 172.16.1.11}"

echo "[edge-router] diverting client-bound replies via attacker ${ATTACKER_IP}"
for c in ${CLIENTS}; do
    ip route replace "${c}/32" via "${ATTACKER_IP}"
done

echo "[edge-router] routes:"
ip route

exec sleep infinity
