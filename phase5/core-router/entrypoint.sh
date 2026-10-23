#!/bin/bash
set -e

echo "[core-router] interfaces:"
ip -4 addr show

case "${INTERCEPT_MODE:-false}" in
    true|TRUE|1|yes|YES)
        echo "[core-router] diverting resolver-bound traffic via attacker"
        ip route replace 172.16.2.10/32 via 172.16.2.100
        ;;
    false|FALSE|0|no|NO|"")
        echo "[core-router] normal routing; removing diversion"
        ip route del 172.16.2.10/32 2>/dev/null || true
        ;;
    *)
        echo "[core-router] invalid INTERCEPT_MODE=${INTERCEPT_MODE}" >&2
        exit 1
        ;;
esac

echo "[core-router] routes:"
ip route

exec sleep infinity