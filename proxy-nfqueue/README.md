# NFQUEUE Proxy (verdict-only baseline)

This proxy uses Linux **NFQUEUE** to divert packets to user space, logs if enabled, and immediately returns an `ACCEPT` verdict. It does **not** terminate or re-dial TCP connections; the kernel continues forwarding the **same packet** after the verdict.

## Features

- **NFQUEUE verdict semantics**: enqueue → userspace verdict → kernel continues.
- **No TCP termination**: no proxy sockets, no re-injection.
- **Minimal overhead**: fast `ACCEPT` verdict path with optional logging.
- **K8s-safe iptables scripts**: additive rules only (no table flush).

## Requirements

- Linux with netfilter + NFQUEUE support.
- `CAP_NET_ADMIN` (run as root or `setcap 'cap_net_admin=+ep' ./proxy-nfqueue`).

## Build

```bash
go build -o proxy-nfqueue .
```

## Run

```bash
sudo ./proxy-nfqueue -queue-num 100 -copymode packet
```

### Useful flags

- `-queue-num`: NFQUEUE number (default: `100`)
- `-copymode`: `packet|meta|none`
- `-log-5tuple`: best-effort 5-tuple logging
- `-af-family`: `unspec|inet|inet6`

## iptables (apply/remove)

These scripts add **only** the rules needed for TCP/11000 and remove only those rules later.
They do **not** flush or overwrite any tables/chains (safe for Kubernetes).

```bash
./apply_iptables_local.sh
./remove_iptables_local.sh
```

Optional: set a specific queue number for rules:

```bash
QUEUE_NUM=100 ./apply_iptables_local.sh
```

The rules target both `--dport 11000` and `--sport 11000` in `INPUT` and `OUTPUT`, so request and response packets are enqueued.

## Local test

```bash
# Terminal 1: server
nc -l -p 11000

# Terminal 2: apply rules and run proxy
./apply_iptables_local.sh
sudo ./proxy-nfqueue

# Terminal 3: client
echo "hello" | nc 127.0.0.1 11000
```

You should see per-packet debug logs while the client/server still communicate normally.

## Notes

- If you stop the proxy while rules are installed, `--queue-bypass` keeps traffic flowing.
- `proxyuser` is created to allow an OUTPUT exclusion rule; this avoids enqueuing the proxy's own traffic.
