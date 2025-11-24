package element

import (
	"context"
)

// RPCElement defines the interface for RPC middleware elements
// Elements can intercept and modify RPC requests and responses
type RPCElement interface {
	// ProcessRequest processes the request before it's sent to the server
	ProcessRequest(ctx context.Context, req *RPCRequest) (*RPCRequest, context.Context, error)

	// ProcessResponse processes the response after it's received from the server
	ProcessResponse(ctx context.Context, resp *RPCResponse) (*RPCResponse, context.Context, error)

	// Name returns the name of the RPC element
	Name() string
}

// RPCRequest represents an RPC request with metadata
type RPCRequest struct {
	ID          uint64 // Unique identifier for the request
	ServiceName string // Name of the service being called
	Method      string // Name of the method being called
	Payload     any    // RPC payload
}

// RPCResponse represents an RPC response with result or error
type RPCResponse struct {
	ID     uint64 // Unique identifier matching the request
	Result any    // Response result (nil if error occurred)
	Error  error  // Error if the RPC failed
}
