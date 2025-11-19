#!/bin/bash

# Script to generate TLS certificates for ARPC-TCP testing
# This generates:
# - CA certificate and key
# - Server certificate and key (signed by CA)
# - Client certificate and key (signed by CA)

set -e

# Configuration
CERT_DIR="${CERT_DIR:-./certs}"
CA_KEY="${CERT_DIR}/ca-key.pem"
CA_CERT="${CERT_DIR}/ca-cert.pem"
SERVER_KEY="${CERT_DIR}/server-key.pem"
SERVER_CERT="${CERT_DIR}/server-cert.pem"
SERVER_CSR="${CERT_DIR}/server.csr"
CLIENT_KEY="${CERT_DIR}/client-key.pem"
CLIENT_CERT="${CERT_DIR}/client-cert.pem"
CLIENT_CSR="${CERT_DIR}/client.csr"

# Default values
DOMAIN="${DOMAIN:-localhost}"
# Additional domains/IPs (comma-separated) - useful for K8s
ADDITIONAL_DOMAINS="${ADDITIONAL_DOMAINS:-}"
ADDITIONAL_IPS="${ADDITIONAL_IPS:-}"
VALIDITY_DAYS="${VALIDITY_DAYS:-365}"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}Generating TLS certificates for ARPC-TCP${NC}"
echo "Certificate directory: ${CERT_DIR}"
echo "Primary domain: ${DOMAIN}"
if [ -n "${ADDITIONAL_DOMAINS}" ]; then
    echo "Additional domains: ${ADDITIONAL_DOMAINS}"
fi
if [ -n "${ADDITIONAL_IPS}" ]; then
    echo "Additional IPs: ${ADDITIONAL_IPS}"
fi
echo "Validity: ${VALIDITY_DAYS} days"
echo ""

# Create certificate directory
mkdir -p "${CERT_DIR}"

# Generate CA private key
echo -e "${GREEN}[1/8] Generating CA private key...${NC}"
openssl genrsa -out "${CA_KEY}" 4096

# Generate CA certificate
echo -e "${GREEN}[2/8] Generating CA certificate...${NC}"
openssl req -new -x509 -days "${VALIDITY_DAYS}" \
    -key "${CA_KEY}" \
    -out "${CA_CERT}" \
    -subj "/C=US/ST=CA/L=San Francisco/O=ARPC-TCP/CN=ARPC-TCP CA"

# Generate server private key
echo -e "${GREEN}[3/8] Generating server private key...${NC}"
openssl genrsa -out "${SERVER_KEY}" 4096

# Generate server certificate signing request
echo -e "${GREEN}[4/8] Generating server certificate signing request...${NC}"
openssl req -new -key "${SERVER_KEY}" \
    -out "${SERVER_CSR}" \
    -subj "/C=US/ST=CA/L=San Francisco/O=ARPC-TCP/CN=${DOMAIN}"

# Generate server certificate (signed by CA)
echo -e "${GREEN}[5/8] Generating server certificate (signed by CA)...${NC}"

# Build SAN entries
SAN_ENTRIES="DNS.1 = ${DOMAIN}\nDNS.2 = localhost\nIP.1 = 127.0.0.1\nIP.2 = ::1"

# Add additional domains
if [ -n "${ADDITIONAL_DOMAINS}" ]; then
    DNS_COUNT=2
    IFS=',' read -ra DOMAIN_ARRAY <<< "${ADDITIONAL_DOMAINS}"
    for domain in "${DOMAIN_ARRAY[@]}"; do
        domain=$(echo "$domain" | xargs) # trim whitespace
        if [ -n "$domain" ]; then
            DNS_COUNT=$((DNS_COUNT + 1))
            SAN_ENTRIES="${SAN_ENTRIES}\nDNS.${DNS_COUNT} = ${domain}"
        fi
    done
fi

# Add additional IPs
if [ -n "${ADDITIONAL_IPS}" ]; then
    IP_COUNT=2
    IFS=',' read -ra IP_ARRAY <<< "${ADDITIONAL_IPS}"
    for ip in "${IP_ARRAY[@]}"; do
        ip=$(echo "$ip" | xargs) # trim whitespace
        if [ -n "$ip" ]; then
            IP_COUNT=$((IP_COUNT + 1))
            SAN_ENTRIES="${SAN_ENTRIES}\nIP.${IP_COUNT} = ${ip}"
        fi
    done
fi

# Create temporary extfile for SAN entries
EXTFILE=$(mktemp)
cat > "${EXTFILE}" <<EOF
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
$(echo -e "${SAN_ENTRIES}")
EOF

openssl x509 -req -days "${VALIDITY_DAYS}" \
    -in "${SERVER_CSR}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${SERVER_CERT}" \
    -extensions v3_req \
    -extfile "${EXTFILE}"

rm -f "${EXTFILE}"

# Generate client private key
echo -e "${GREEN}[6/8] Generating client private key...${NC}"
openssl genrsa -out "${CLIENT_KEY}" 4096

# Generate client certificate signing request
echo -e "${GREEN}[7/8] Generating client certificate signing request...${NC}"
openssl req -new -key "${CLIENT_KEY}" \
    -out "${CLIENT_CSR}" \
    -subj "/C=US/ST=CA/L=San Francisco/O=ARPC-TCP/CN=ARPC-TCP Client"

# Generate client certificate (signed by CA)
echo -e "${GREEN}[8/8] Generating client certificate (signed by CA)...${NC}"
openssl x509 -req -days "${VALIDITY_DAYS}" \
    -in "${CLIENT_CSR}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${CLIENT_CERT}" \
    -extensions v3_req \
    -extfile <(
        cat <<EOF
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF
    )

# Clean up CSR files and serial number files
rm -f "${SERVER_CSR}" "${CLIENT_CSR}"
rm -f "${CERT_DIR}"/*.srl 2>/dev/null || true

# Set appropriate permissions
chmod 600 "${CA_KEY}" "${SERVER_KEY}" "${CLIENT_KEY}"
chmod 644 "${CA_CERT}" "${SERVER_CERT}" "${CLIENT_CERT}"

echo ""
echo -e "${GREEN}✓ Certificate generation complete!${NC}"
echo ""
echo "Generated files:"
echo "  CA Certificate:    ${CA_CERT}"
echo "  CA Key:            ${CA_KEY}"
echo "  Server Certificate: ${SERVER_CERT}"
echo "  Server Key:        ${SERVER_KEY}"
echo "  Client Certificate: ${CLIENT_CERT}"
echo "  Client Key:        ${CLIENT_KEY}"
echo ""
echo -e "${YELLOW}To use TLS with ARPC-TCP:${NC}"
echo ""
echo "Server (set these environment variables):"
echo "  export ARPC_TLS_ENABLED=true"
echo "  export ARPC_TLS_CERT_FILE=${SERVER_CERT}"
echo "  export ARPC_TLS_KEY_FILE=${SERVER_KEY}"
echo ""
echo "Client (set these environment variables):"
echo "  export ARPC_TLS_ENABLED=true"
echo "  export ARPC_TLS_CA_FILE=${CA_CERT}"
echo ""
echo "Or for testing with insecure verification:"
echo "  export ARPC_TLS_ENABLED=true"
echo "  export ARPC_TLS_SKIP_VERIFY=true"
echo ""
echo -e "${YELLOW}For Kubernetes deployments:${NC}"
echo ""
echo "Example - generate certs for K8s service:"
echo "  DOMAIN=kvstore.default.svc.cluster.local \\"
echo "  ADDITIONAL_DOMAINS='kvstore,kvstore.default,kvstore.default.svc' \\"
echo "  ./scripts/generate-certs.sh"
echo ""
echo "Example - with multiple services and IPs:"
echo "  DOMAIN=myservice.default.svc.cluster.local \\"
echo "  ADDITIONAL_DOMAINS='myservice,myservice.default,*.default.svc.cluster.local' \\"
echo "  ADDITIONAL_IPS='10.96.0.1,10.96.0.2' \\"
echo "  ./scripts/generate-certs.sh"
echo ""
echo "Note: The certificate includes these SAN entries:"
echo "  - Primary domain: ${DOMAIN}"
echo "  - localhost (for local testing)"
echo "  - 127.0.0.1 and ::1 (for local testing)"
if [ -n "${ADDITIONAL_DOMAINS}" ]; then
    echo "  - Additional domains: ${ADDITIONAL_DOMAINS}"
fi
if [ -n "${ADDITIONAL_IPS}" ]; then
    echo "  - Additional IPs: ${ADDITIONAL_IPS}"
fi
echo ""

