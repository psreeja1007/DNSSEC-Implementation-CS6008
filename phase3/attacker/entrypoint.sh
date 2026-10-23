#!/bin/bash
set -e

# IMPORTANT: ip_forward stays OFF here. We are not acting as an IP router —
# core-router's diversion route Ethernet-addresses resolver-bound replies
# straight to us; if the kernel forwarded them on its own, our pcap-based
# interceptor would never see them (this was the bug: ip_forward=1 meant
# the kernel silently relayed everything and the queue/filter never fired).
# ./interceptor is the thing that does the relaying now, frame by frame.
sysctl -w net.ipv4.ip_forward=0 >/dev/null

echo "[attacker] interfaces:"
ip -4 addr show

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
