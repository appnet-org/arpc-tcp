#!/bin/bash

echo "Removing sidecar proxy rules..."

# Remove the specific rules we added (in reverse order of how they were added)

# Remove OUTPUT rule for outbound interception
sudo iptables -t nat -D OUTPUT -p tcp --dport 11000:11100 -m owner ! --uid-owner proxyuser -j REDIRECT --to-ports 15002 2>/dev/null

# Remove PREROUTING rule for inbound interception
sudo iptables -t nat -D PREROUTING -p tcp --dport 11000:11100 -j REDIRECT --to-ports 15006 2>/dev/null

# Remove conntrack rules
sudo iptables -t nat -D OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN 2>/dev/null
sudo iptables -t nat -D PREROUTING -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN 2>/dev/null

# Remove DNS exclusion rules
sudo iptables -t nat -D OUTPUT -p tcp --dport 53 -j RETURN 2>/dev/null
sudo iptables -t nat -D OUTPUT -p udp --dport 53 -j RETURN 2>/dev/null

# Remove loopback exclusion rules (new specific rules for proxy ports)
sudo iptables -t nat -D OUTPUT -o lo -p tcp --dport 15006 -j RETURN 2>/dev/null
sudo iptables -t nat -D OUTPUT -o lo -p tcp --dport 15002 -j RETURN 2>/dev/null

# Remove old loopback exclusion rule (if it exists)
sudo iptables -t nat -D OUTPUT -o lo -j RETURN 2>/dev/null

# Remove proxy user exclusion rule
sudo iptables -t nat -D OUTPUT -m owner --uid-owner proxyuser -j RETURN 2>/dev/null

echo "Sidecar proxy rules removed."
echo ""
echo "Current NAT OUTPUT rules:"
sudo iptables -t nat -L OUTPUT -n --line-numbers
echo ""
echo "Current NAT PREROUTING rules:"
sudo iptables -t nat -L PREROUTING -n --line-numbers

