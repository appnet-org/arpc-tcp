#!/bin/bash
set -euo pipefail

CHAIN="ARPC_NFQUEUE_11000"
COMMENT="arpc-nfqueue"
PROXY_USER="proxyuser"
TABLE="mangle"

echo "Removing NFQUEUE rules for TCP/11000..."

delete_rule() {
	if sudo iptables -w -t "${TABLE}" -C "$@" 2>/dev/null; then
		sudo iptables -w -t "${TABLE}" -D "$@"
	fi
}

delete_rule INPUT -p tcp --dport 11000 -j "${CHAIN}" -m comment --comment "${COMMENT}"
delete_rule INPUT -p tcp --sport 11000 -j "${CHAIN}" -m comment --comment "${COMMENT}"
delete_rule OUTPUT -p tcp --dport 11000 -j "${CHAIN}" -m comment --comment "${COMMENT}"
delete_rule OUTPUT -p tcp --sport 11000 -j "${CHAIN}" -m comment --comment "${COMMENT}"
delete_rule OUTPUT -m owner --uid-owner "${PROXY_USER}" -j RETURN -m comment --comment "${COMMENT}"

if sudo iptables -w -t "${TABLE}" -L "${CHAIN}" -n >/dev/null 2>&1; then
	sudo iptables -w -t "${TABLE}" -F "${CHAIN}"
	sudo iptables -w -t "${TABLE}" -X "${CHAIN}"
fi

echo "NFQUEUE rules removed."
