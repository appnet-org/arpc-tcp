#!/bin/bash
set -euo pipefail

QUEUE_NUM="${QUEUE_NUM:-100}"
CHAIN="ARPC_NFQUEUE_11000"
COMMENT="arpc-nfqueue"
PROXY_USER="proxyuser"
TABLE="mangle"

echo "Applying NFQUEUE rules for TCP/11000..."

id -u "${PROXY_USER}" >/dev/null 2>&1 || sudo useradd -r -s /sbin/nologin "${PROXY_USER}"

if ! sudo iptables -w -t "${TABLE}" -L "${CHAIN}" -n >/dev/null 2>&1; then
	sudo iptables -w -t "${TABLE}" -N "${CHAIN}"
fi

add_rule() {
	if ! sudo iptables -w -t "${TABLE}" -C "$@" 2>/dev/null; then
		sudo iptables -w -t "${TABLE}" -A "$@"
	fi
}

add_rule "${CHAIN}" -p tcp --dport 11000 -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass -m comment --comment "${COMMENT}"
add_rule "${CHAIN}" -p tcp --sport 11000 -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass -m comment --comment "${COMMENT}"

add_rule OUTPUT -m owner --uid-owner "${PROXY_USER}" -j RETURN -m comment --comment "${COMMENT}"

add_rule INPUT -p tcp --dport 11000 -j "${CHAIN}" -m comment --comment "${COMMENT}"
add_rule INPUT -p tcp --sport 11000 -j "${CHAIN}" -m comment --comment "${COMMENT}"
add_rule OUTPUT -p tcp --dport 11000 -j "${CHAIN}" -m comment --comment "${COMMENT}"
add_rule OUTPUT -p tcp --sport 11000 -j "${CHAIN}" -m comment --comment "${COMMENT}"

echo "NFQUEUE rules applied (queue ${QUEUE_NUM})."
