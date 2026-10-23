#!/bin/bash
set -e

# attacker sits on resolver_net; needs routes to reach other subnets
# for relaying
ip route replace 172.16.1.0/24 via 172.16.2.2
ip route replace 172.16.3.0/24 via 172.16.2.3

echo "[attacker] routes:"
ip route
echo "[attacker] route checks:"
ip route get 172.16.1.10
ip route get 172.16.3.10

case "${INTERCEPT_MODE:-false}" in
    true|TRUE|1|yes|YES)
        mode=intercept
        ;;
    false|FALSE|0|no|NO|"")
        mode=normal
        ;;
    *)
        echo "[attacker] invalid INTERCEPT_MODE='${INTERCEPT_MODE}'; use true or false" >&2
        exit 1
        ;;
esac

echo "[attacker] intercept enabled: ${INTERCEPT_MODE:-false}"
echo "[attacker] mode: ${mode}"
exec ./interceptor "${mode}"