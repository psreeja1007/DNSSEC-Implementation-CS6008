#!/bin/bash
set -e

# Phase 6 leaves the upstream (resolver <-> authoritative) path untouched.
# The attack is entirely on the last mile, handled by edge-router + attacker.

echo "[core-router] interfaces:"
ip -4 addr show
echo "[core-router] routes:"
ip route

exec sleep infinity
