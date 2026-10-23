#!/bin/bash
set -e

sysctl -w net.ipv4.ip_forward=0 >/dev/null

echo "[attacker] interfaces:"
ip -4 addr show

case "${ATTACK_MODE:-normal}" in
    normal)    mode=normal    ;;
    intercept) mode=intercept ;;   # Phase 2/3 style: forge A only
    strip)     mode=strip     ;;   # Phase 4: strip DNSSEC RRs + forge A
    *) echo "[attacker] invalid ATTACK_MODE='${ATTACK_MODE}'" >&2; exit 1 ;;
esac

echo "[attacker] mode: ${mode}"
exec ./interceptor "${mode}"