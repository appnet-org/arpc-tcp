# Transparent TCP Proxy with TPROXY

This proxy implements a transparent TCP proxy that does NOT terminate TCP connections. Unlike `proxy-tcp` which accepts connections and creates new ones, this proxy uses Linux TPROXY to forward packets transparently while preserving the original connection.

## Features

- **TPROXY Support**: Uses Linux TPROXY to intercept packets without terminating connections
- **Transparent Forwarding**: Client sees the original destination IP/port, not the proxy's
- **No Connection Termination**: Preserves the original TCP connection semantics
- **Packet-Level Interception**: Works at the network layer with iptables TPROXY rules
- **Simple Architecture**: No element chain or data inspection (packet forwarding only)

## How It Works

The proxy listens on configured ports (default: 15002, 15006) and handles connections as follows:

1. **TPROXY Interception**: iptables TPROXY rules redirect packets to the proxy's listening socket
2. **Connection Acceptance**: Proxy accepts connections with `IP_TRANSPARENT` socket option
3. **Original Destination Retrieval**: Uses `IP_ORIGDSTADDR` to get the original destination address
4. **Transparent Relay**: Connects to original destination and relays data bidirectionally
5. **No Data Inspection**: Data is forwarded as-is without modification

## Architecture

Unlike `proxy-tcp` which terminates connections:

- **proxy-tcp**: Accepts client connection → Creates new connection to target → Relays data
- **proxy-tcp-transparent**: Intercepts client connection → Gets original destination → Relays data (client sees original destination)

## iptables Configuration

To use with TPROXY, configure rules like this:

```bash
# Create a system user named 'proxyuser' with no login shell
sudo useradd -r -s /usr/sbin/nologin proxyuser

# Enable IP forwarding (required for TPROXY)
sudo sysctl -w net.ipv4.ip_forward=1

# Create routing table for TPROXY
sudo ip route add local 0.0.0.0/0 dev lo table 100
sudo ip rule add fwmark 1 lookup 100

# 1. Intercept INBOUND traffic (from outside)
# Mark packets and send to TPROXY
sudo iptables -t mangle -N DIVERT
sudo iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
sudo iptables -t mangle -A DIVERT -j MARK --set-mark 1
sudo iptables -t mangle -A DIVERT -j ACCEPT

# TPROXY rule for inbound traffic (port 11000 -> proxy port 15006)
sudo iptables -t mangle -A PREROUTING -p tcp --dport 11000 \
    -j TPROXY --on-port 15006 --tproxy-mark 0x1/0x1

# 2. Intercept OUTBOUND traffic (from local apps)
# Exclude proxy's own traffic
sudo iptables -t mangle -A OUTPUT -m owner --uid-owner proxyuser -j RETURN

# TPROXY rule for outbound traffic (port 11000 -> proxy port 15002)
sudo iptables -t mangle -A OUTPUT -p tcp --dport 11000 \
    -j TPROXY --on-port 15002 --on-ip 127.0.0.1 --tproxy-mark 0x1/0x1
```

## Quick Verification

```bash
# Check mangle table rules
sudo iptables -t mangle -L -n -v

# Check routing table
ip route show table 100

# Check routing rules
ip rule show
```

## Configuration

### Environment Variables

- `LOG_LEVEL`: Logging level (default: `debug`)
- `LOG_FORMAT`: Logging format (default: `console`)

### Command Line Flags

- `-ports`: Comma-separated list of ports to listen on (default: `15002,15006`)
- `-interface`: Network interface to bind to (not used yet, defaults to all)

### Default Ports

The proxy listens on ports: `15002`, `15006`

## Building

```bash
go build -o proxy-tcp-transparent .
```

## Running

```bash
# Run with TPROXY interception (requires root or CAP_NET_ADMIN)
sudo -u proxyuser ./proxy-tcp-transparent
```

**Note**: TPROXY requires `CAP_NET_ADMIN` capability. The proxy must be run as root or with appropriate capabilities.

## Cleanup

```bash
# Remove TPROXY rules
sudo iptables -t mangle -D OUTPUT -p tcp --dport 11000 -j TPROXY --on-port 15002 --on-ip 127.0.0.1 --tproxy-mark 0x1/0x1
sudo iptables -t mangle -D PREROUTING -p tcp --dport 11000 -j TPROXY --on-port 15006 --tproxy-mark 0x1/0x1

# Remove DIVERT chain
sudo iptables -t mangle -F DIVERT
sudo iptables -t mangle -X DIVERT

# Remove routing rules
sudo ip rule del fwmark 1 lookup 100
sudo ip route del local 0.0.0.0/0 dev lo table 100

# (Optional) Delete the user if you don't need it anymore
sudo userdel proxyuser
```

## Technical Details

### TPROXY vs REDIRECT

| Feature | REDIRECT (proxy-tcp) | TPROXY (proxy-tcp-transparent) |
|---------|---------------------|--------------------------------|
| Connection handling | Terminates (accepts + dials) | Transparent (forwards packets) |
| iptables table | `nat` | `mangle` |
| Client sees | Proxy's IP/port | Original destination IP/port |
| Data inspection | Yes (element chain) | No (packet forwarding only) |
| TLS termination | Yes | No |
| Complexity | Higher | Lower |

### IP_TRANSPARENT Socket Option

The proxy uses `IP_TRANSPARENT` socket option which allows:
- Binding to non-local addresses
- Accepting connections destined for remote IPs
- Preserving original destination information

### Original Destination Retrieval

The proxy retrieves the original destination using `IP_ORIGDSTADDR` socket option:
1. Accepts connection on TPROXY socket
2. Calls `getsockopt` with `IP_ORIGDSTADDR`
3. Parses the returned `sockaddr_in` structure
4. Extracts IP and port to connect to original destination

## Limitations

- Currently supports IPv4 only (IPv6 support can be added)
- Requires `CAP_NET_ADMIN` capability (must run as root or with capabilities)
- Requires IP forwarding to be enabled (`net.ipv4.ip_forward=1`)
- Requires routing table setup for TPROXY to work
- No data inspection or modification (by design)
- No TLS termination (connections are transparent)

## Comparison with proxy-tcp

| Feature | proxy-tcp | proxy-tcp-transparent |
|---------|-----------|----------------------|
| Connection termination | Yes | No |
| iptables method | REDIRECT (nat table) | TPROXY (mangle table) |
| Client sees | Proxy address | Original destination |
| Data inspection | Yes (element chain) | No |
| TLS termination | Yes | No |
| Use case | Full proxy with inspection | Transparent forwarding |

Both proxies share:
- iptables interception
- Bidirectional forwarding
- Connection management
- Logging infrastructure

