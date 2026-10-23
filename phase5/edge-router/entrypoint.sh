#!/bin/bash
set -e

# Enable forwarding between the client subnet and the resolver subnet.
# No NAT: both interfaces keep their real addresses end to end.

echo "[edge-router] interfaces:"
ip -4 addr show
echo "[edge-router] routes:"
ip route

exec sleep infinity
