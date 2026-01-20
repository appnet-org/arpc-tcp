#!/bin/bash

echo "Removing transparent proxy TPROXY rules..."

# Remove TPROXY rules (in reverse order)

# Remove OUTPUT TPROXY rule
sudo iptables -t mangle -D OUTPUT -p tcp --dport 11000:11100 \
    -j TPROXY --on-port 15002 --on-ip 127.0.0.1 --tproxy-mark 0x1/0x1 2>/dev/null

# Remove PREROUTING TPROXY rule
sudo iptables -t mangle -D PREROUTING -p tcp --dport 11000:11100 \
    -j TPROXY --on-port 15006 --tproxy-mark 0x1/0x1 2>/dev/null

# Remove conntrack rules
sudo iptables -t mangle -D OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN 2>/dev/null
sudo iptables -t mangle -D PREROUTING -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN 2>/dev/null

# Remove DNS exclusion rules
sudo iptables -t mangle -D OUTPUT -p tcp --dport 53 -j RETURN 2>/dev/null
sudo iptables -t mangle -D OUTPUT -p udp --dport 53 -j RETURN 2>/dev/null

# Remove loopback exclusion rules
sudo iptables -t mangle -D OUTPUT -o lo -p tcp --dport 15006 -j RETURN 2>/dev/null
sudo iptables -t mangle -D OUTPUT -o lo -p tcp --dport 15002 -j RETURN 2>/dev/null

# Remove proxy user exclusion rule
sudo iptables -t mangle -D OUTPUT -m owner --uid-owner proxyuser -j RETURN 2>/dev/null

# Remove DIVERT chain rules
sudo iptables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null

# Flush and delete DIVERT chain
sudo iptables -t mangle -F DIVERT 2>/dev/null
sudo iptables -t mangle -X DIVERT 2>/dev/null

# Remove routing rule
sudo ip rule del fwmark 1 lookup 100 2>/dev/null

# Remove routing table (optional - may be used by other services)
# sudo ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null

echo "Transparent proxy TPROXY rules removed."
echo ""
echo "Current mangle OUTPUT rules:"
sudo iptables -t mangle -L OUTPUT -n --line-numbers
echo ""
echo "Current mangle PREROUTING rules:"
sudo iptables -t mangle -L PREROUTING -n --line-numbers
echo ""
echo "Remaining routing rules:"
ip rule show | grep "lookup 100" || echo "No routing rules for table 100"

