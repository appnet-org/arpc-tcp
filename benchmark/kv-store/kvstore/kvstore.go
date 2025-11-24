package main

import (
	"context"
	"os"
	"strconv"
	"sync"

	kv "github.com/appnet-org/arpc-tcp/benchmark/kv-store/symphony"
	"github.com/appnet-org/arpc-tcp/pkg/logging"
	"github.com/appnet-org/arpc-tcp/pkg/rpc"
	"github.com/appnet-org/arpc-tcp/pkg/rpc/element"
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
	// Initialize logging with configuration from environment variables
	if err := logging.Init(getLoggingConfig()); err != nil {
		panic(err)
	}

	serializer := &serializer.SymphonySerializer{}
	server, err := rpc.NewServer(":11000", serializer, nil)
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
	// Create handlers that match the new element-aware interface
	getHandler := func(srv any, ctx context.Context, dec func(any) error, rpcReq *element.RPCRequest, chain *element.RPCElementChain) (*element.RPCResponse, context.Context, error) {
		req := new(kv.GetRequest)
		if err := dec(req); err != nil {
			return nil, ctx, err
		}

		// Set the payload in rpcReq for element processing
		rpcReq.Payload = req

		// Process request through element chain
		rpcReq, ctx, err := chain.ProcessRequest(ctx, rpcReq)
		if err != nil {
			return nil, ctx, err
		}

		// Call the actual service method
		result, ctx, err := srv.(kv.KVServiceServer).Get(ctx, rpcReq.Payload.(*kv.GetRequest))
		if err != nil {
			return nil, ctx, err
		}

		// Create response
		rpcResp := &element.RPCResponse{
			ID:     rpcReq.ID,
			Result: result,
			Error:  nil,
		}

		// Process response through element chain
		rpcResp, ctx, err = chain.ProcessResponse(ctx, rpcResp)
		return rpcResp, ctx, err
	}

	setHandler := func(srv any, ctx context.Context, dec func(any) error, rpcReq *element.RPCRequest, chain *element.RPCElementChain) (*element.RPCResponse, context.Context, error) {
		req := new(kv.SetRequest)
		if err := dec(req); err != nil {
			return nil, ctx, err
		}

		// Set the payload in rpcReq for element processing
		rpcReq.Payload = req

		// Process request through element chain
		rpcReq, ctx, err := chain.ProcessRequest(ctx, rpcReq)
		if err != nil {
			return nil, ctx, err
		}

		// Call the actual service method
		result, ctx, err := srv.(kv.KVServiceServer).Set(ctx, rpcReq.Payload.(*kv.SetRequest))
		if err != nil {
			return nil, ctx, err
		}

		// Create response
		rpcResp := &element.RPCResponse{
			ID:     rpcReq.ID,
			Result: result,
			Error:  nil,
		}

		// Process response through element chain
		rpcResp, ctx, err = chain.ProcessResponse(ctx, rpcResp)
		return rpcResp, ctx, err
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
