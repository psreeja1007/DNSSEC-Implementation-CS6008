#!/bin/bash
set -e

# Enable forwarding between the resolver subnet and the authoritative subnet.
# No NAT: both interfaces keep their real addresses end to end.

echo "[core-router] interfaces:"
ip -4 addr show
echo "[core-router] routes:"
ip route

exec sleep infinity
