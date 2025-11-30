# Certificate Generation Guide for KV-Store

This guide shows you how to generate TLS certificates for the kv-store application with mTLS support.

## Quick Start

### For Local Testing

Generate certificates for localhost:

```bash
# From the project root
cd /users/xzhu/arpc-tcp

# Generate certificates in the kv-store certs directory
CERT_DIR=./benchmark/kv-store/certs ./scripts/generate-certs.sh
# Make sure the proxyuser can use this file
chmod 644 ./benchmark/kv-store/certs/server-key.pem
chmod 644 ./benchmark/kv-store/certs/server-cert.pem
```

This will create:
- `benchmark/kv-store/certs/ca-cert.pem` - CA certificate
- `benchmark/kv-store/certs/ca-key.pem` - CA private key
- `benchmark/kv-store/certs/server-cert.pem` - Server certificate
- `benchmark/kv-store/certs/server-key.pem` - Server private key
- `benchmark/kv-store/certs/client-cert.pem` - Client certificate
- `benchmark/kv-store/certs/client-key.pem` - Client private key

### Using the Generated Certificates

#### Start Server with mTLS:

```bash
cd benchmark/kv-store

go run kvstore/*.go \
  -mtls \
  -tls-cert-file=./certs/server-cert.pem \
  -tls-key-file=./certs/server-key.pem \
  -tls-ca-file=./certs/ca-cert.pem
```

#### Start Client with mTLS:

```bash
cd benchmark/kv-store

go run frontend/*.go \
  -mtls \
  -tls-ca-file=./certs/ca-cert.pem \
  -tls-client-cert-file=./certs/client-cert.pem \
  -tls-client-key-file=./certs/client-key.pem \
  -server=localhost:11000
```

## Certificate Generation Options

### Environment Variables

The script supports these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_DIR` | `./certs` | Directory where certificates will be generated |
| `DOMAIN` | `localhost` | Primary domain for the server certificate |
| `ADDITIONAL_DOMAINS` | (none) | Comma-separated list of additional domains |
| `ADDITIONAL_IPS` | (none) | Comma-separated list of additional IP addresses |
| `VALIDITY_DAYS` | `365` | Certificate validity period in days |

### Examples

#### 1. Basic Local Testing

```bash
CERT_DIR=./benchmark/kv-store/certs ./scripts/generate-certs.sh
```

Generates certificates valid for:
- `localhost`
- `127.0.0.1`
- `::1`

#### 2. Custom Domain

```bash
CERT_DIR=./benchmark/kv-store/certs \
DOMAIN=my-kvstore.local \
./scripts/generate-certs.sh
```

#### 3. Kubernetes Service

For Kubernetes deployments, generate certificates with the service DNS name:

```bash
CERT_DIR=./benchmark/kv-store/certs \
DOMAIN=kvstore.default.svc.cluster.local \
ADDITIONAL_DOMAINS='kvstore,kvstore.default,kvstore.default.svc' \
./scripts/generate-certs.sh
```

#### 4. Multiple Domains and IPs

```bash
CERT_DIR=./benchmark/kv-store/certs \
DOMAIN=kvstore.example.com \
ADDITIONAL_DOMAINS='kvstore,*.example.com,internal.kvstore' \
ADDITIONAL_IPS='10.0.0.1,192.168.1.100' \
VALIDITY_DAYS=730 \
./scripts/generate-certs.sh
```

## Generated Files

After running the script, you'll have these files in your `CERT_DIR`:

```
certs/
├── ca-cert.pem          # CA certificate (public)
├── ca-key.pem           # CA private key (keep secret!)
├── server-cert.pem      # Server certificate (public)
├── server-key.pem       # Server private key (keep secret!)
├── client-cert.pem      # Client certificate (public)
└── client-key.pem       # Client private key (keep secret!)
```

**Security Note:** Files ending in `-key.pem` are private keys and should be kept secure. They have permissions set to `600` (read/write for owner only).

## Using Certificates with Command-Line Flags

### Server (kvstore)

```bash
go run kvstore/*.go \
  -mtls \
  -tls-cert-file=./certs/server-cert.pem \
  -tls-key-file=./certs/server-key.pem \
  -tls-ca-file=./certs/ca-cert.pem
```

### Client (frontend)

```bash
go run frontend/*.go \
  -mtls \
  -tls-ca-file=./certs/ca-cert.pem \
  -tls-client-cert-file=./certs/client-cert.pem \
  -tls-client-key-file=./certs/client-key.pem \
  -server=localhost:11000
```

## Using Certificates with Environment Variables

Alternatively, you can use environment variables instead of flags:

### Server

```bash
export ARPC_TLS_ENABLED=true
export ARPC_TLS_CERT_FILE=./certs/server-cert.pem
export ARPC_TLS_KEY_FILE=./certs/server-key.pem
export ARPC_TLS_CA_FILE=./certs/ca-cert.pem  # Required for mTLS

go run kvstore/*.go
```

### Client

```bash
export ARPC_TLS_ENABLED=true
export ARPC_TLS_CA_FILE=./certs/ca-cert.pem
export ARPC_TLS_CLIENT_CERT_FILE=./certs/client-cert.pem
export ARPC_TLS_CLIENT_KEY_FILE=./certs/client-key.pem

go run frontend/*.go -server=localhost:11000
```

## Kubernetes Deployment

### 1. Generate Certificates

```bash
CERT_DIR=./benchmark/kv-store/certs \
DOMAIN=kvstore.default.svc.cluster.local \
ADDITIONAL_DOMAINS='kvstore,kvstore.default,kvstore.default.svc' \
./scripts/generate-certs.sh
```

### 2. Create Kubernetes Secret

```bash
kubectl create secret generic kvstore-tls-certs \
  --from-file=ca-cert.pem=./benchmark/kv-store/certs/ca-cert.pem \
  --from-file=server-cert.pem=./benchmark/kv-store/certs/server-cert.pem \
  --from-file=server-key.pem=./benchmark/kv-store/certs/server-key.pem \
  --from-file=client-cert.pem=./benchmark/kv-store/certs/client-cert.pem \
  --from-file=client-key.pem=./benchmark/kv-store/certs/client-key.pem
```

### 3. Update Deployment Manifest

In your Kubernetes deployment manifest, mount the secret and set environment variables or use command-line flags:

```yaml
containers:
- name: kvstore
  command: ["/app/kvstore"]
  args:
    - "-mtls"
    - "-tls-cert-file=/app/certs/server-cert.pem"
    - "-tls-key-file=/app/certs/server-key.pem"
    - "-tls-ca-file=/app/certs/ca-cert.pem"
  volumeMounts:
  - name: tls-certs
    mountPath: /app/certs
    readOnly: true
volumes:
- name: tls-certs
  secret:
    secretName: kvstore-tls-certs
```

## Verifying Certificates

You can verify the generated certificates using OpenSSL:

### View CA Certificate

```bash
openssl x509 -in ./benchmark/kv-store/certs/ca-cert.pem -text -noout
```

### View Server Certificate

```bash
openssl x509 -in ./benchmark/kv-store/certs/server-cert.pem -text -noout
```

### View Client Certificate

```bash
openssl x509 -in ./benchmark/kv-store/certs/client-cert.pem -text -noout
```

### Check Certificate Validity Period

```bash
openssl x509 -in ./benchmark/kv-store/certs/server-cert.pem -noout -dates
```

## Troubleshooting

### Certificate Not Found

Make sure the certificate directory exists and the script has write permissions:

```bash
mkdir -p ./benchmark/kv-store/certs
chmod +x ./scripts/generate-certs.sh
```

### Certificate Expired

Regenerate certificates with a longer validity period:

```bash
VALIDITY_DAYS=730 CERT_DIR=./benchmark/kv-store/certs ./scripts/generate-certs.sh
```

### Wrong Domain in Certificate

If you need to change the domain, regenerate the certificates with the correct domain:

```bash
CERT_DIR=./benchmark/kv-store/certs \
DOMAIN=your-new-domain.com \
./scripts/generate-certs.sh
```

### Permission Denied

The script sets appropriate permissions automatically. If you need to fix them manually:

```bash
chmod 600 ./benchmark/kv-store/certs/*-key.pem
chmod 644 ./benchmark/kv-store/certs/*.pem
```

## Security Best Practices

1. **Never commit private keys** to version control
2. **Use strong key sizes** (script uses 4096-bit keys)
3. **Rotate certificates** before expiration
4. **Protect private keys** with appropriate file permissions
5. **Use separate CAs** for production and testing
6. **In production**, use a proper PKI rather than self-signed certificates

## Complete Example Workflow

Here's a complete example for local testing:

```bash
# 1. Generate certificates
cd /users/xzhu/arpc-tcp
CERT_DIR=./benchmark/kv-store/certs ./scripts/generate-certs.sh

# 2. Start server (in one terminal)
cd benchmark/kv-store
go run kvstore/*.go \
  -mtls \
  -tls-cert-file=./certs/server-cert.pem \
  -tls-key-file=./certs/server-key.pem \
  -tls-ca-file=./certs/ca-cert.pem

# 3. Start client (in another terminal)
cd benchmark/kv-store
go run frontend/*.go \
  -mtls \
  -tls-ca-file=./certs/ca-cert.pem \
  -tls-client-cert-file=./certs/client-cert.pem \
  -tls-client-key-file=./certs/client-key.pem \
  -server=localhost:11000

# 4. Test with curl
curl "http://localhost:8080/?op=SET&key=test123&key_size=10&value_size=20"
curl "http://localhost:8080/?op=GET&key=test123&key_size=10&value_size=20"
```

