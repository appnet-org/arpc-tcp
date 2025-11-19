## Run the Client and Server

Start the server:

```bash
go run kvstore/*.go 
```

In a **separate terminal**, run the client:

```bash
go run frontend/*.go 
```

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