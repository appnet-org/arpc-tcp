## Run the Client and Server

### Basic Usage (No TLS)

Start the server:

```bash
go run kvstore/*.go 
```

In a **separate terminal**, run the client:

```bash
go run frontend/*.go 
```

### Using TLS (One-Way Authentication)

Start the server with TLS:

```bash
go run kvstore/*.go \
  -tls \
  -tls-cert-file=./certs/server-cert.pem \
  -tls-key-file=./certs/server-key.pem
```

Run the client with TLS:

```bash
go run frontend/*.go \
  -tls \
  -tls-ca-file=./certs/ca-cert.pem \
  -server=localhost:11000
```

### Using mTLS (Mutual TLS Authentication)

Start the server with mTLS:

```bash
go run kvstore/*.go \
  -mtls \
  -tls-cert-file=./certs/server-cert.pem \
  -tls-key-file=./certs/server-key.pem \
  -tls-ca-file=./certs/ca-cert.pem
```

Run the client with mTLS:

```bash
go run frontend/*.go \
  -mtls \
  -tls-ca-file=./certs/ca-cert.pem \
  -tls-client-cert-file=./certs/client-cert.pem \
  -tls-client-key-file=./certs/client-key.pem \
  -server=localhost:11000
```

### Command-Line Flags

#### Server (kvstore) Flags:
- `-mtls`: Enable mutual TLS (mTLS) authentication
- `-tls`: Enable TLS (one-way or mTLS)
- `-tls-cert-file`: Path to server certificate file (required for TLS)
- `-tls-key-file`: Path to server private key file (required for TLS)
- `-tls-ca-file`: Path to CA certificate file (required for mTLS to verify client certs)
- `-listen`: Address to listen on (default: `:11000`)

#### Client (frontend) Flags:
- `-mtls`: Enable mutual TLS (mTLS) authentication
- `-tls`: Enable TLS (one-way or mTLS)
- `-tls-ca-file`: Path to CA certificate file (for verifying server cert)
- `-tls-client-cert-file`: Path to client certificate file (required for mTLS)
- `-tls-client-key-file`: Path to client private key file (required for mTLS)
- `-tls-skip-verify`: Skip server certificate verification (testing only)
- `-server`: Server address to connect to (default: `kvstore.default.svc.cluster.local:11000`)

**Note:** Flags take precedence over environment variables. You can still use environment variables (`ARPC_TLS_ENABLED`, `ARPC_TLS_CERT_FILE`, etc.) if you prefer.

## 4. Test
```bash
# Set
curl "http://localhost:8080/?op=SET&key=82131353f9ddc8c6&key_size=48&value_size=87"

# Get 
curl "http://localhost:8080/?op=GET&key=82131353f9ddc8c6&key_size=48&value_size=87"

# For Kubernetes:
curl "http://10.96.88.88:80/?op=SET&key=82131353f9ddc8c6&key_size=48&value_size=87"
curl "http://10.96.88.88:80/?op=GET&key=82131353f9ddc8c6&key_size=48&value_size=87"
```

## TLS-enabled KV Store Deployment for Kubernetes

### Prerequisites:

1. Generate TLS certificates using the generate-certs.sh script:
   ```bash
   DOMAIN=kvstore.default.svc.cluster.local \
   ADDITIONAL_DOMAINS='kvstore,kvstore.default,kvstore.default.svc' \
   CERT_DIR=./benchmark/kv-store/certs \
   ./scripts/generate-certs.sh
   ```

2. Create the Kubernetes secret from the generated certificates:
   ```bash
   kubectl create secret generic kvstore-tls-certs \
     --from-file=ca-cert.pem=./benchmark/kv-store/certs/ca-cert.pem \
     --from-file=server-cert.pem=./benchmark/kv-store/certs/server-cert.pem \
     --from-file=server-key.pem=./benchmark/kv-store/certs/server-key.pem \
     --from-file=client-cert.pem=./benchmark/kv-store/certs/client-cert.pem \
     --from-file=client-key.pem=./benchmark/kv-store/certs/client-key.pem
   ```

3. Deploy this manifest:
   ```bash
   kubectl apply -f manifest/kvstore-tls.yaml
   ```

### Updating Certificates

To update certificates (e.g., after expiration), regenerate them and update the secret:
```bash
kubectl create secret generic kvstore-tls-certs \
  --from-file=ca-cert.pem=./benchmark/kv-store/certs/ca-cert.pem \
  --from-file=server-cert.pem=./benchmark/kv-store/certs/server-cert.pem \
  --from-file=server-key.pem=./benchmark/kv-store/certs/server-key.pem \
  --from-file=client-cert.pem=./benchmark/kv-store/certs/client-cert.pem \
  --from-file=client-key.pem=./benchmark/kv-store/certs/client-key.pem \
  --dry-run=client -o yaml | kubectl apply -f -
```