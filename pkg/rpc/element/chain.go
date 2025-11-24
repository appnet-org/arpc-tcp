package element

import (
	"context"
)

// RPCElementChain represents a chain of RPC elements that process requests and responses
type RPCElementChain struct {
	elements []RPCElement
}

// NewRPCElementChain creates a new chain of RPC elements
func NewRPCElementChain(elements ...RPCElement) *RPCElementChain {
	return &RPCElementChain{
		elements: elements,
	}
}

// ProcessRequest processes the request through all RPC elements in forward order
// Each element can modify the request and context before passing to the next element
// If any element returns an error, processing stops and the error is returned
func (c *RPCElementChain) ProcessRequest(ctx context.Context, req *RPCRequest) (*RPCRequest, context.Context, error) {
	var err error

	// Process through elements in forward order (first to last)
	for _, element := range c.elements {
		req, ctx, err = element.ProcessRequest(ctx, req)
		if err != nil {
			return req, ctx, err
		}
	}

	return req, ctx, nil
}

// ProcessResponse processes the response through all RPC elements in reverse order
// Each element can modify the response and context before passing to the next element
// If any element returns an error, processing stops and the error is returned
func (c *RPCElementChain) ProcessResponse(ctx context.Context, resp *RPCResponse) (*RPCResponse, context.Context, error) {
	var err error

	// Process through elements in reverse order (last to first)
	for i := len(c.elements) - 1; i >= 0; i-- {
		resp, ctx, err = c.elements[i].ProcessResponse(ctx, resp)
		if err != nil {
			return resp, ctx, err
		}
	}

	return resp, ctx, nil
}
