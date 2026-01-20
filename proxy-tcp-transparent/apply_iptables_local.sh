#!/bin/bash

echo "Applying transparent proxy TPROXY rules..."

# Create proxy user if it doesn't exist
id -u proxyuser >/dev/null 2>&1 || sudo useradd -r -s /sbin/nologin proxyuser

# Enable IP forwarding (required for TPROXY)
sudo sysctl -w net.ipv4.ip_forward=1

# Create routing table for TPROXY (if it doesn't exist)
if ! ip route show table 100 >/dev/null 2>&1; then
    sudo ip route add local 0.0.0.0/0 dev lo table 100
    echo "Created routing table 100"
fi

# Add routing rule for TPROXY (if it doesn't exist)
if ! ip rule show | grep -q "fwmark 0x1 lookup 100"; then
    sudo ip rule add fwmark 1 lookup 100
    echo "Added routing rule for fwmark 1"
fi

# Create DIVERT chain in mangle table if it doesn't exist
if ! sudo iptables -t mangle -L DIVERT >/dev/null 2>&1; then
    sudo iptables -t mangle -N DIVERT
    echo "Created DIVERT chain"
fi

# Clear existing DIVERT chain rules (if any)
sudo iptables -t mangle -F DIVERT 2>/dev/null

# Set up DIVERT chain rules
sudo iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
sudo iptables -t mangle -A DIVERT -j MARK --set-mark 1
sudo iptables -t mangle -A DIVERT -j ACCEPT

# Exclude proxy's own traffic from interception
sudo iptables -t mangle -A OUTPUT -m owner --uid-owner proxyuser -j RETURN

# Exclude loopback traffic to proxy ports (prevents hairpin loops)
sudo iptables -t mangle -A OUTPUT -o lo -p tcp --dport 15002 -j RETURN
sudo iptables -t mangle -A OUTPUT -o lo -p tcp --dport 15006 -j RETURN

# Exclude DNS traffic (recommended)
sudo iptables -t mangle -A OUTPUT -p udp --dport 53 -j RETURN
sudo iptables -t mangle -A OUTPUT -p tcp --dport 53 -j RETURN

# Preserve existing connections
sudo iptables -t mangle -A PREROUTING -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
sudo iptables -t mangle -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN

# INBOUND INTERCEPTION (for traffic *into* the app)
# TPROXY rule: redirect traffic destined for port 11000-11100 to proxy port 15006
sudo iptables -t mangle -A PREROUTING -p tcp --dport 11000:11100 \
    -j TPROXY --on-port 15006 --tproxy-mark 0x1/0x1

# OUTBOUND INTERCEPTION (for app-initiated connections)
# TPROXY rule: redirect traffic destined for port 11000-11100 to proxy port 15002
sudo iptables -t mangle -A OUTPUT -p tcp --dport 11000:11100 \
    -j TPROXY --on-port 15002 --on-ip 127.0.0.1 --tproxy-mark 0x1/0x1

echo "Transparent proxy TPROXY rules applied successfully."
echo ""
echo "Current mangle PREROUTING rules:"
sudo iptables -t mangle -L PREROUTING -n --line-numbers
echo ""
echo "Current mangle OUTPUT rules:"
sudo iptables -t mangle -L OUTPUT -n --line-numbers
echo ""
echo "Routing table 100:"
ip route show table 100
echo ""
echo "Routing rules:"
ip rule show | grep "lookup 100"

