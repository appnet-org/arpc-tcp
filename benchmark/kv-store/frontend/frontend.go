package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	kv "github.com/appnet-org/arpc-tcp/benchmark/kv-store/symphony"
	"github.com/appnet-org/arpc-tcp/pkg/logging"
	"github.com/appnet-org/arpc-tcp/pkg/rpc"
	"github.com/appnet-org/arpc-tcp/pkg/serializer"
	"go.uber.org/zap"
)

// Deterministic random string generator from key_id and desired length
func generateDeterministicString(keyID string, length int) string {
	hash := sha256.Sum256([]byte(keyID))
	repeatCount := (length + len(hash)*2 - 1) / (len(hash) * 2)
	hexStr := strings.Repeat(hex.EncodeToString(hash[:]), repeatCount)
	return hexStr[:length]
}

// arpcTCPKVServiceClient implements KVServiceClient using arpc-tcp's RPC client
type arpcTCPKVServiceClient struct {
	client *rpc.Client
}

func (c *arpcTCPKVServiceClient) Get(ctx context.Context, req *kv.GetRequest) (*kv.GetResponse, error) {
	resp := new(kv.GetResponse)
	if err := c.client.Call(ctx, "KVService", "Get", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *arpcTCPKVServiceClient) Set(ctx context.Context, req *kv.SetRequest) (*kv.SetResponse, error) {
	resp := new(kv.SetResponse)
	if err := c.client.Call(ctx, "KVService", "Set", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

var kvClient kv.KVServiceClient

// getLoggingConfig reads logging configuration from environment variables with defaults
func getLoggingConfig() *logging.Config {
	level := os.Getenv("LOG_LEVEL")
	if level == "" {
		level = "debug"
	}

	format := os.Getenv("LOG_FORMAT")
	if format == "" {
		format = "console"
	}

	return &logging.Config{
		Level:  level,
		Format: format,
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	op := strings.ToLower(r.URL.Query().Get("op"))
	keyID := r.URL.Query().Get("key")
	keySizeStr := r.URL.Query().Get("key_size")
	valueSizeStr := r.URL.Query().Get("value_size")

	keySize, _ := strconv.Atoi(keySizeStr)
	valueSize, _ := strconv.Atoi(valueSizeStr)

	if keyID == "" {
		http.Error(w, "key parameter is required", http.StatusBadRequest)
		return
	}

	// Generate deterministic key/value strings
	keyStr := generateDeterministicString(keyID+"-key", keySize)
	valueStr := generateDeterministicString(keyID+"-value", valueSize)

	logging.Debug("Received HTTP request",
		zap.String("op", op),
		zap.String("key_id", keyID),
		zap.Int("key_size", keySize),
		zap.Int("value_size", valueSize),
	)

	switch op {
	case "get":
		req := &kv.GetRequest{Key: keyStr}
		resp, err := kvClient.Get(context.Background(), req)
		if err != nil {
			logging.Error("Get RPC call failed", zap.Error(err))
			http.Error(w, fmt.Sprintf("Get RPC failed: %v", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Value for key_id '%s' (key='%s'): %s\n", keyID, keyStr, resp.Value)

	case "set":
		req := &kv.SetRequest{Key: keyStr, Value: valueStr}
		resp, err := kvClient.Set(context.Background(), req)
		if err != nil {
			logging.Error("Set RPC call failed", zap.Error(err))
			http.Error(w, fmt.Sprintf("Set RPC failed: %v", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Set key_id '%s' (key='%s') to value='%s'. Response: %s\n",
			keyID, keyStr, valueStr, resp.Value)

	default:
		http.Error(w, "Invalid operation. Use op=GET or op=SET", http.StatusBadRequest)
	}
}

func main() {
	// Command-line flags for mTLS configuration
	var (
		enableMTLS        = flag.Bool("mtls", false, "Enable mutual TLS (mTLS) authentication")
		tlsEnabled        = flag.Bool("tls", false, "Enable TLS (one-way or mTLS)")
		tlsCAFile         = flag.String("tls-ca-file", "", "Path to CA certificate file (for verifying server cert)")
		tlsClientCertFile = flag.String("tls-client-cert-file", "", "Path to client certificate file (required for mTLS)")
		tlsClientKeyFile  = flag.String("tls-client-key-file", "", "Path to client private key file (required for mTLS)")
		tlsSkipVerify     = flag.Bool("tls-skip-verify", true, "Skip server certificate verification (testing only)")
		serverAddr        = flag.String("server", "kvstore.default.svc.cluster.local:11000", "Server address to connect to")
	)
	flag.Parse()

	err := logging.Init(getLoggingConfig())
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logging: %v", err))
	}

	// Configure TLS/mTLS from flags or environment variables
	// Flags take precedence over environment variables
	if *tlsEnabled || *enableMTLS {
		os.Setenv("ARPC_TLS_ENABLED", "true")
	}

	if *tlsCAFile != "" {
		os.Setenv("ARPC_TLS_CA_FILE", *tlsCAFile)
	} else if *tlsEnabled || *enableMTLS {
		// If TLS is enabled but CA file not provided via flag, check environment
		if os.Getenv("ARPC_TLS_CA_FILE") == "" {
			logging.Warn("TLS enabled but no CA file specified. Use -tls-ca-file flag or ARPC_TLS_CA_FILE env var")
		}
	}

	if *enableMTLS {
		// mTLS requires client certificates
		if *tlsClientCertFile != "" {
			os.Setenv("ARPC_TLS_CLIENT_CERT_FILE", *tlsClientCertFile)
		} else if os.Getenv("ARPC_TLS_CLIENT_CERT_FILE") == "" {
			logging.Fatal("mTLS enabled but no client certificate specified. Use -tls-client-cert-file flag or ARPC_TLS_CLIENT_CERT_FILE env var")
		}

		if *tlsClientKeyFile != "" {
			os.Setenv("ARPC_TLS_CLIENT_KEY_FILE", *tlsClientKeyFile)
		} else if os.Getenv("ARPC_TLS_CLIENT_KEY_FILE") == "" {
			logging.Fatal("mTLS enabled but no client key specified. Use -tls-client-key-file flag or ARPC_TLS_CLIENT_KEY_FILE env var")
		}

		logging.Info("mTLS enabled for client",
			zap.String("ca_file", os.Getenv("ARPC_TLS_CA_FILE")),
			zap.String("client_cert", os.Getenv("ARPC_TLS_CLIENT_CERT_FILE")),
			zap.String("client_key", os.Getenv("ARPC_TLS_CLIENT_KEY_FILE")),
		)
	} else if *tlsEnabled {
		logging.Info("TLS enabled for client (one-way)",
			zap.String("ca_file", os.Getenv("ARPC_TLS_CA_FILE")),
		)
	}

	if *tlsSkipVerify {
		os.Setenv("ARPC_TLS_SKIP_VERIFY", "true")
	}

	serializer := &serializer.SymphonySerializer{}
	client, err := rpc.NewClient(serializer, *serverAddr)
	if err != nil {
		logging.Fatal("Failed to create RPC client", zap.Error(err))
	}
	kvClient = &arpcTCPKVServiceClient{client: client}

	http.HandleFunc("/", handler)

	logging.Info("HTTP server listening", zap.String("addr", ":8080"))
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logging.Fatal("HTTP server failed", zap.Error(err))
	}
}
