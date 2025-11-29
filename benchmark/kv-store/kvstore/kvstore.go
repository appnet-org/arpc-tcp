package main

import (
	"context"
	"flag"
	"os"
	"strconv"
	"sync"

	kv "github.com/appnet-org/arpc-tcp/benchmark/kv-store/symphony"
	"github.com/appnet-org/arpc-tcp/pkg/logging"
	"github.com/appnet-org/arpc-tcp/pkg/rpc"
	"github.com/appnet-org/arpc-tcp/pkg/serializer"
	"go.uber.org/zap"
)

// KVService implementation
type kvServer struct {
	mu          sync.RWMutex
	data        map[string]string
	maxSize     int
	accessOrder []string // For LRU eviction
}

func NewKVServer(maxSize int) *kvServer {
	if maxSize <= 0 {
		maxSize = 1000 // Default max size
	}
	return &kvServer{
		data:        make(map[string]string),
		maxSize:     maxSize,
		accessOrder: make([]string, 0, maxSize),
	}
}

func (s *kvServer) Get(ctx context.Context, req *kv.GetRequest) (*kv.GetResponse, context.Context, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := req.GetKey()
	logging.Debug("Server got Get request", zap.String("key", key))

	value, exists := s.data[key]
	if !exists {
		value = "" // Return empty string if key doesn't exist
	} else {
		// Move to end of access order for LRU
		s.moveToEnd(key)
	}

	resp := &kv.GetResponse{
		Value: value,
	}

	logging.Debug("Server returning value for key", zap.String("key", key), zap.String("value", value))
	return resp, context.Background(), nil
}

func (s *kvServer) Set(ctx context.Context, req *kv.SetRequest) (*kv.SetResponse, context.Context, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := req.GetKey()
	value := req.GetValue()
	logging.Debug("Server got Set request", zap.String("key", key), zap.String("value", value))

	// Check if we need to evict an item
	if len(s.data) >= s.maxSize {
		if _, exists := s.data[key]; !exists {
			s.evictLRU()
		}
	}

	s.data[key] = value
	s.moveToEnd(key)

	resp := &kv.SetResponse{
		Value: value,
	}

	logging.Debug("Server set key to value", zap.String("key", key), zap.String("value", value))
	return resp, context.Background(), nil
}

// moveToEnd moves the key to the end of the access order (most recently used)
func (s *kvServer) moveToEnd(key string) {
	// Remove from current position if it exists
	for i, k := range s.accessOrder {
		if k == key {
			s.accessOrder = append(s.accessOrder[:i], s.accessOrder[i+1:]...)
			break
		}
	}
	// Add to end
	s.accessOrder = append(s.accessOrder, key)
}

// evictLRU removes the least recently used item
func (s *kvServer) evictLRU() {
	if len(s.accessOrder) == 0 {
		return
	}

	// Remove the first (oldest) item
	keyToRemove := s.accessOrder[0]
	s.accessOrder = s.accessOrder[1:]
	delete(s.data, keyToRemove)

	logging.Debug("Evicted LRU key", zap.String("key", keyToRemove))
}

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

func main() {
	// Command-line flags for mTLS configuration
	var (
		enableMTLS    = flag.Bool("mtls", false, "Enable mutual TLS (mTLS) authentication")
		tlsEnabled    = flag.Bool("tls", false, "Enable TLS (one-way or mTLS)")
		tlsCertFile   = flag.String("tls-cert-file", "", "Path to server certificate file (required for TLS)")
		tlsKeyFile    = flag.String("tls-key-file", "", "Path to server private key file (required for TLS)")
		tlsCAFile     = flag.String("tls-ca-file", "", "Path to CA certificate file (required for mTLS to verify client certs)")
		listenAddr    = flag.String("listen", ":11000", "Address to listen on")
	)
	flag.Parse()

	// Initialize logging with configuration from environment variables
	if err := logging.Init(getLoggingConfig()); err != nil {
		panic(err)
	}

	// Configure TLS/mTLS from flags or environment variables
	// Flags take precedence over environment variables
	if *tlsEnabled || *enableMTLS {
		os.Setenv("ARPC_TLS_ENABLED", "true")
	}

	if *tlsCertFile != "" {
		os.Setenv("ARPC_TLS_CERT_FILE", *tlsCertFile)
	} else if *tlsEnabled || *enableMTLS {
		// If TLS is enabled but cert file not provided via flag, check environment
		if os.Getenv("ARPC_TLS_CERT_FILE") == "" {
			logging.Fatal("TLS enabled but no server certificate specified. Use -tls-cert-file flag or ARPC_TLS_CERT_FILE env var")
		}
	}

	if *tlsKeyFile != "" {
		os.Setenv("ARPC_TLS_KEY_FILE", *tlsKeyFile)
	} else if *tlsEnabled || *enableMTLS {
		// If TLS is enabled but key file not provided via flag, check environment
		if os.Getenv("ARPC_TLS_KEY_FILE") == "" {
			logging.Fatal("TLS enabled but no server key specified. Use -tls-key-file flag or ARPC_TLS_KEY_FILE env var")
		}
	}

	if *enableMTLS {
		// mTLS requires CA file for client certificate verification
		if *tlsCAFile != "" {
			os.Setenv("ARPC_TLS_CA_FILE", *tlsCAFile)
		} else if os.Getenv("ARPC_TLS_CA_FILE") == "" {
			logging.Fatal("mTLS enabled but no CA file specified. Use -tls-ca-file flag or ARPC_TLS_CA_FILE env var")
		}

		logging.Info("mTLS enabled for server",
			zap.String("cert_file", os.Getenv("ARPC_TLS_CERT_FILE")),
			zap.String("key_file", os.Getenv("ARPC_TLS_KEY_FILE")),
			zap.String("ca_file", os.Getenv("ARPC_TLS_CA_FILE")),
		)
	} else if *tlsEnabled {
		logging.Info("TLS enabled for server (one-way)",
			zap.String("cert_file", os.Getenv("ARPC_TLS_CERT_FILE")),
			zap.String("key_file", os.Getenv("ARPC_TLS_KEY_FILE")),
		)
	}

	serializer := &serializer.SymphonySerializer{}
	server, err := rpc.NewServer(*listenAddr, serializer)
	if err != nil {
		logging.Fatal("Failed to start server", zap.Error(err))
	}

	// Create KV server with max size constraint (configurable via environment variable)
	maxSize := 1000 // Default max size
	if maxSizeEnv := os.Getenv("KV_MAX_SIZE"); maxSizeEnv != "" {
		if parsed, err := strconv.Atoi(maxSizeEnv); err == nil && parsed > 0 {
			maxSize = parsed
		}
	}

	kvServer := NewKVServer(maxSize)

	// Manually register the service with arpc-tcp's server
	// Create handlers that adapt arpc-tcp's simpler interface to the server implementation
	getHandler := func(srv any, ctx context.Context, dec func(any) error) (resp any, err error) {
		req := new(kv.GetRequest)
		if err := dec(req); err != nil {
			return nil, err
		}
		result, _, err := srv.(kv.KVServiceServer).Get(ctx, req)
		return result, err
	}

	setHandler := func(srv any, ctx context.Context, dec func(any) error) (resp any, err error) {
		req := new(kv.SetRequest)
		if err := dec(req); err != nil {
			return nil, err
		}
		result, _, err := srv.(kv.KVServiceServer).Set(ctx, req)
		return result, err
	}

	server.RegisterService(&rpc.ServiceDesc{
		ServiceName: "KVService",
		ServiceImpl: kvServer,
		Methods: map[string]*rpc.MethodDesc{
			"Get": {
				MethodName: "Get",
				Handler:    getHandler,
			},
			"Set": {
				MethodName: "Set",
				Handler:    setHandler,
			},
		},
	}, kvServer)

	server.Start()
}
