#!/bin/bash
set -euo pipefail

QUEUE_NUM="${QUEUE_NUM:-100}"
PROXY_UID="${PROXY_UID:-1337}"
PORT="${PORT:-11000}"
CHAIN="ARPC_NFQUEUE_${PORT}"
COMMENT="arpc-nfqueue"
TABLE="mangle"

echo "Applying NFQUEUE rules for TCP/${PORT}..."

# Create custom chain if it doesn't exist
if ! iptables -w -t "${TABLE}" -L "${CHAIN}" -n >/dev/null 2>&1; then
	iptables -w -t "${TABLE}" -N "${CHAIN}"
fi

add_rule() {
	if ! iptables -w -t "${TABLE}" -C "$@" 2>/dev/null; then
		iptables -w -t "${TABLE}" -A "$@"
	fi
}

# NFQUEUE rules in custom chain
add_rule "${CHAIN}" -p tcp --dport "${PORT}" -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass -m comment --comment "${COMMENT}"
add_rule "${CHAIN}" -p tcp --sport "${PORT}" -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass -m comment --comment "${COMMENT}"

# Exclude proxy's own traffic to prevent loops
add_rule OUTPUT -m owner --uid-owner "${PROXY_UID}" -j RETURN -m comment --comment "${COMMENT}"

# Jump to custom chain for matching traffic
add_rule INPUT -p tcp --dport "${PORT}" -j "${CHAIN}" -m comment --comment "${COMMENT}"
add_rule INPUT -p tcp --sport "${PORT}" -j "${CHAIN}" -m comment --comment "${COMMENT}"
add_rule OUTPUT -p tcp --dport "${PORT}" -j "${CHAIN}" -m comment --comment "${COMMENT}"
add_rule OUTPUT -p tcp --sport "${PORT}" -j "${CHAIN}" -m comment --comment "${COMMENT}"

echo "NFQUEUE rules applied (queue ${QUEUE_NUM})."