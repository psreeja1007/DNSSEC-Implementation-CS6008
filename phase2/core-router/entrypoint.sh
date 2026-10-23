#!/bin/bash
set -e

# Enable forwarding between the resolver subnet and the authoritative subnet.
# No NAT: both interfaces keep their real addresses end to end.

# Divert replies destined for the resolver through the attacker.
ip route replace 172.16.2.10/32 via 172.16.2.100

echo "[core-router] interfaces:"
ip -4 addr show
echo "[core-router] routes:"
ip route
echo "[core-router] route check for resolver:"
ip route get 172.16.2.10

exec sleep infinity