#!/bin/bash
set -e

# ip_forward stays OFF: edge-router's diversion route Ethernet-addresses the
# client-bound replies straight to us, and the pcap interceptor is the thing
# that relays them on, frame by frame. If the kernel forwarded them it would
# bypass our capture entirely.
sysctl -w net.ipv4.ip_forward=0 >/dev/null

export ATTACKER_IP="${ATTACKER_IP:-172.16.1.100}"
export CLIENT_IPS="${CLIENT_IPS:-172.16.1.10,172.16.1.11}"

echo "[attacker] interfaces:"
ip -4 addr show

case "${INTERCEPT_MODE:-false}" in
    true|TRUE|1|yes|YES) mode=intercept ;;
    false|FALSE|0|no|NO|"") mode=normal ;;
    *)
        echo "[attacker] invalid INTERCEPT_MODE='${INTERCEPT_MODE}'; use true or false" >&2
        exit 1 ;;
esac

echo "[attacker] attacker_ip=${ATTACKER_IP} clients=${CLIENT_IPS}"
echo "[attacker] intercept enabled: ${INTERCEPT_MODE:-false}  mode: ${mode}"

exec ./interceptor "${mode}"
