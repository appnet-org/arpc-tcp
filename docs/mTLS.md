# Enabling Mutual TLS (mTLS) in ARPC-TCP

This guide explains how to enable mutual TLS (mTLS) authentication in ARPC-TCP, which provides bidirectional certificate-based authentication between clients and servers.

## Overview

mTLS requires both the client and server to present certificates:
- **Server**: Presents its certificate to the client (standard TLS)
- **Client**: Presents its certificate to the server (mTLS addition)
- Both certificates are verified against a trusted CA

## Prerequisites

1. Generate certificates using the provided script (which already creates client certificates):
   ```bash
   ./scripts/generate-certs.sh
   ```

   This generates:
   - `ca-cert.pem` - CA certificate
   - `server-cert.pem` - Server certificate
   - `server-key.pem` - Server private key
   - `client-cert.pem` - Client certificate
   - `client-key.pem` - Client private key

## Server Configuration

To enable mTLS on the server, set these environment variables:

```bash
# Enable TLS
export ARPC_TLS_ENABLED=true

# Server certificate and key (required for TLS)
export ARPC_TLS_CERT_FILE=/path/to/server-cert.pem
export ARPC_TLS_KEY_FILE=/path/to/server-key.pem

# CA certificate for verifying client certificates (required for mTLS)
export ARPC_TLS_CA_FILE=/path/to/ca-cert.pem
```

When `ARPC_TLS_CA_FILE` is set, the server will:
- Require clients to present a certificate (`ClientAuth = RequireAndVerifyClientCert`)
- Verify client certificates against the provided CA

## Client Configuration

To enable mTLS on the client, set these environment variables:

```bash
# Enable TLS
export ARPC_TLS_ENABLED=true

# CA certificate for verifying server certificate (required for TLS)
export ARPC_TLS_CA_FILE=/path/to/ca-cert.pem

# Client certificate and key (required for mTLS)
export ARPC_TLS_CLIENT_CERT_FILE=/path/to/client-cert.pem
export ARPC_TLS_CLIENT_KEY_FILE=/path/to/client-key.pem
```

## Example: Complete mTLS Setup

### 1. Generate Certificates

```bash
# Generate certificates for localhost
./scripts/generate-certs.sh

# Or for a specific domain (e.g., Kubernetes service)
DOMAIN=myservice.default.svc.cluster.local \
ADDITIONAL_DOMAINS='myservice,myservice.default' \
./scripts/generate-certs.sh
```

### 2. Server Setup

```bash
export ARPC_TLS_ENABLED=true
export ARPC_TLS_CERT_FILE=./certs/server-cert.pem
export ARPC_TLS_KEY_FILE=./certs/server-key.pem
export ARPC_TLS_CA_FILE=./certs/ca-cert.pem

# Run your server
./your-server
```

### 3. Client Setup

```bash
export ARPC_TLS_ENABLED=true
export ARPC_TLS_CA_FILE=./certs/ca-cert.pem
export ARPC_TLS_CLIENT_CERT_FILE=./certs/client-cert.pem
export ARPC_TLS_CLIENT_KEY_FILE=./certs/client-key.pem

# Run your client
./your-client
```

## Kubernetes Deployment Example

Here's an example Kubernetes deployment with mTLS:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: server
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: server
        image: your-image:latest
        env:
        # Enable TLS
        - name: ARPC_TLS_ENABLED
          value: "true"
        # Server certificate
        - name: ARPC_TLS_CERT_FILE
          value: "/app/certs/server-cert.pem"
        - name: ARPC_TLS_KEY_FILE
          value: "/app/certs/server-key.pem"
        # CA for client verification (mTLS)
        - name: ARPC_TLS_CA_FILE
          value: "/app/certs/ca-cert.pem"
        volumeMounts:
        - name: tls-certs
          mountPath: /app/certs
          readOnly: true
      volumes:
      - name: tls-certs
        secret:
          secretName: tls-certs
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: client
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: client
        image: your-image:latest
        env:
        # Enable TLS
        - name: ARPC_TLS_ENABLED
          value: "true"
        # CA for server verification
        - name: ARPC_TLS_CA_FILE
          value: "/app/certs/ca-cert.pem"
        # Client certificate (mTLS)
        - name: ARPC_TLS_CLIENT_CERT_FILE
          value: "/app/certs/client-cert.pem"
        - name: ARPC_TLS_CLIENT_KEY_FILE
          value: "/app/certs/client-key.pem"
        volumeMounts:
        - name: tls-certs
          mountPath: /app/certs
          readOnly: true
      volumes:
      - name: tls-certs
        secret:
          secretName: tls-certs
```

Create the Kubernetes secret:

```bash
kubectl create secret generic tls-certs \
  --from-file=ca-cert.pem=./certs/ca-cert.pem \
  --from-file=server-cert.pem=./certs/server-cert.pem \
  --from-file=server-key.pem=./certs/server-key.pem \
  --from-file=client-cert.pem=./certs/client-cert.pem \
  --from-file=client-key.pem=./certs/client-key.pem
```

## Environment Variables Reference

### Server Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ARPC_TLS_ENABLED` | Yes | Set to `true`, `1`, or `yes` to enable TLS |
| `ARPC_TLS_CERT_FILE` | Yes | Path to server certificate file |
| `ARPC_TLS_KEY_FILE` | Yes | Path to server private key file |
| `ARPC_TLS_CA_FILE` | For mTLS | Path to CA certificate for verifying client certificates |

### Client Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ARPC_TLS_ENABLED` | Yes | Set to `true`, `1`, or `yes` to enable TLS |
| `ARPC_TLS_CA_FILE` | Recommended | Path to CA certificate for verifying server certificate |
| `ARPC_TLS_CLIENT_CERT_FILE` | For mTLS | Path to client certificate file |
| `ARPC_TLS_CLIENT_KEY_FILE` | For mTLS | Path to client private key file |
| `ARPC_TLS_SKIP_VERIFY` | Optional | Set to `true` or `1` to skip server certificate verification (testing only) |

## Differences from Standard TLS

### Standard TLS (One-Way)
- Server presents certificate to client
- Client verifies server certificate
- No client certificate required

**Server config:**
```bash
export ARPC_TLS_ENABLED=true
export ARPC_TLS_CERT_FILE=./certs/server-cert.pem
export ARPC_TLS_KEY_FILE=./certs/server-key.pem
# ARPC_TLS_CA_FILE not set
```

**Client config:**
```bash
export ARPC_TLS_ENABLED=true
export ARPC_TLS_CA_FILE=./certs/ca-cert.pem
# Client certificates not set
```

### mTLS (Mutual TLS)
- Server presents certificate to client
- Client verifies server certificate
- Client presents certificate to server
- Server verifies client certificate

**Server config:**
```bash
export ARPC_TLS_ENABLED=true
export ARPC_TLS_CERT_FILE=./certs/server-cert.pem
export ARPC_TLS_KEY_FILE=./certs/server-key.pem
export ARPC_TLS_CA_FILE=./certs/ca-cert.pem  # Required for mTLS
```

**Client config:**
```bash
export ARPC_TLS_ENABLED=true
export ARPC_TLS_CA_FILE=./certs/ca-cert.pem
export ARPC_TLS_CLIENT_CERT_FILE=./certs/client-cert.pem  # Required for mTLS
export ARPC_TLS_CLIENT_KEY_FILE=./certs/client-key.pem    # Required for mTLS
```

## Troubleshooting

### Server rejects client connections
- Ensure `ARPC_TLS_CA_FILE` is set on the server
- Verify the client certificate is signed by the CA specified in `ARPC_TLS_CA_FILE`
- Check that client certificate has `extendedKeyUsage = clientAuth`

### Client cannot connect to server
- Ensure `ARPC_TLS_CLIENT_CERT_FILE` and `ARPC_TLS_CLIENT_KEY_FILE` are set
- Verify the client certificate is valid and not expired
- Check that the server's `ARPC_TLS_CA_FILE` points to the CA that signed the client certificate

### Certificate verification errors
- Ensure all certificates are signed by the same CA (or use appropriate CA chains)
- Check certificate expiration dates
- Verify certificate file paths are correct

## Security Notes

1. **Never commit certificates or keys to version control**
2. **Use strong key sizes** (the script generates 4096-bit keys)
3. **Rotate certificates regularly** before expiration
4. **Protect private keys** with appropriate file permissions (600)
5. **Use separate CAs for production and testing** environments
6. **In production, use a proper PKI** rather than self-signed certificates

