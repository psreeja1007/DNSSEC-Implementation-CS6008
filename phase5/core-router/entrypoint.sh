#!/bin/bash
set -e

echo "[core-router] interfaces:"
ip -4 addr show

case "${ATTACK_MODE:-normal}" in
    intercept|strip)
        echo "[core-router] attack mode ${ATTACK_MODE}; diverting resolver-bound traffic via attacker"
        ip route replace 172.16.2.10/32 via 172.16.2.100
        ;;
    normal)
        echo "[core-router] normal routing; removing diversion"
        ip route del 172.16.2.10/32 2>/dev/null || true
        ;;
    *)
        echo "[core-router] invalid ATTACK_MODE=${ATTACK_MODE}" >&2
        exit 1
        ;;
esac

echo "[core-router] routes:"
ip route

exec sleep infinity