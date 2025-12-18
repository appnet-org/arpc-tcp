// pkg/rpc/client.go
package rpc

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/appnet-org/arpc-tcp/pkg/logging"
	"github.com/appnet-org/arpc-tcp/pkg/packet"
	"github.com/appnet-org/arpc-tcp/pkg/serializer"
	"github.com/appnet-org/arpc-tcp/pkg/transport"
	"go.uber.org/zap"
)

// responseData holds the response data for a specific RPC call
type responseData struct {
	data       []byte
	rpcID      uint64
	packetType packet.PacketTypeID
	err        error
}

// Client represents an RPC client with a transport and serializer.
type Client struct {
	transport      *transport.TCPTransport
	serializer     serializer.Serializer
	defaultAddr    string
	responseChans  sync.Map // map[uint64]chan *responseData - using sync.Map for better concurrent performance
	dispatcherOnce sync.Once
	stopDispatcher chan struct{}
	dispatcherWg   sync.WaitGroup
}

// NewClient creates a new Client using the given serializer and target address.
// The client will create a TCP connection to the server.
func NewClient(serializer serializer.Serializer, addr string) (*Client, error) {
	t, err := transport.NewTCPClientTransport()
	if err != nil {
		return nil, err
	}
	return &Client{
		transport:      t,
		serializer:     serializer,
		defaultAddr:    addr,
		stopDispatcher: make(chan struct{}),
	}, nil
}

// NewClientWithLocalAddr creates a new Client using the given serializer, target address, and local address.
// Note: For TCP, the local address is not used in the same way as UDP.
// This function is kept for API compatibility but the localAddr parameter is ignored.
func NewClientWithLocalAddr(serializer serializer.Serializer, addr, localAddr string) (*Client, error) {
	// For TCP, we don't bind to a local address in the same way
	// The OS will assign a local port when we connect
	return NewClient(serializer, addr)
}

// Transport returns the underlying TCP transport for cleanup purposes
func (c *Client) Transport() *transport.TCPTransport {
	return c.transport
}

// frameRequest constructs a binary message with
// [serviceLen(2B)][service][methodLen(2B)][method][payload]
func (c *Client) frameRequest(service, method string, payload []byte) ([]byte, error) {
	// Pre-calculate buffer size (headers: 2 + 2 = 4 bytes)
	totalSize := 4 + len(service) + len(method) + len(payload)
	buf := make([]byte, totalSize)

	// service
	binary.LittleEndian.PutUint16(buf[0:2], uint16(len(service)))
	copy(buf[2:], service)

	// method
	methodStart := 2 + len(service)
	binary.LittleEndian.PutUint16(buf[methodStart:methodStart+2], uint16(len(method)))
	copy(buf[methodStart+2:], method)

	// payload
	payloadStart := methodStart + 2 + len(method)
	copy(buf[payloadStart:], payload)

	return buf, nil
}

func (c *Client) parseFramedResponse(data []byte) (service string, method string, payload []byte, err error) {
	offset := 0

	// Parse service name
	if len(data) < 2 {
		return "", "", nil, fmt.Errorf("invalid response (too short for serviceLen)")
	}
	serviceLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if offset+serviceLen > len(data) {
		return "", "", nil, fmt.Errorf("invalid response (truncated service)")
	}
	service = string(data[offset : offset+serviceLen])
	offset += serviceLen

	// Parse method name
	if offset+2 > len(data) {
		return "", "", nil, fmt.Errorf("invalid response (too short for methodLen)")
	}
	methodLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if offset+methodLen > len(data) {
		return "", "", nil, fmt.Errorf("invalid response (truncated method)")
	}
	method = string(data[offset : offset+methodLen])
	offset += methodLen

	payload = data[offset:]
	return service, method, payload, nil
}

func (c *Client) handleErrorPacket(errMsg string, errType packet.PacketTypeID) error {
	var rpcErrType RPCErrorType
	if errType == packet.PacketTypeError {
		rpcErrType = RPCFailError
	} else {
		rpcErrType = RPCUnknownError
	}
	return &RPCError{Type: rpcErrType, Reason: errMsg}
}

func (c *Client) handleResponsePacket(data []byte, rpcID uint64, resp any) error {
	// Parse framed response: extract service, method, payload
	_, _, respPayloadBytes, err := c.parseFramedResponse(data)
	if err != nil {
		return fmt.Errorf("failed to parse framed response: %w", err)
	}

	// Deserialize the response into resp
	if err := c.serializer.Unmarshal(respPayloadBytes, resp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	logging.Debug("Successfully received response", zap.Uint64("rpcID", rpcID))

	return nil
}

// startDispatcher starts a goroutine that reads responses from the transport
// and routes them to the appropriate waiting call based on RPC ID.
func (c *Client) startDispatcher() {
	c.dispatcherOnce.Do(func() {
		c.dispatcherWg.Add(1)
		go func() {
			defer c.dispatcherWg.Done()
			for {
				// Check if we should stop before blocking on receive
				select {
				case <-c.stopDispatcher:
					return
				default:
				}

				// Receive will block until data is available
				data, _, respID, packetTypeID, err := c.transport.Receive(packet.MaxTCPPayloadSize)

				// Check stop signal again after receive
				select {
				case <-c.stopDispatcher:
					return
				default:
				}

				if err != nil {
					// If there's an error, notify all waiting calls
					c.responseChans.Range(func(key, value any) bool {
						rpcID := key.(uint64)
						ch := value.(chan *responseData)
						select {
						case ch <- &responseData{err: fmt.Errorf("transport error: %w", err)}:
						default:
						}
						c.responseChans.Delete(rpcID)
						return true
					})
					return
				}

				if data == nil {
					continue // Still waiting for fragments
				}

				// Route the response to the waiting call
				// Use LoadAndDelete for atomic lookup and removal
				if chVal, exists := c.responseChans.LoadAndDelete(respID); exists {
					ch := chVal.(chan *responseData)
					// Pre-allocate responseData to avoid allocation in hot path
					respData := &responseData{
						data:       data,
						rpcID:      respID,
						packetType: packetTypeID,
					}
					select {
					case ch <- respData:
						// Response delivered successfully
					default:
						// Channel is full or closed
						logging.Warn("Failed to deliver response, channel blocked",
							zap.Uint64("rpcID", respID))
					}
				} else {
					logging.Debug("Received response for unknown RPC ID",
						zap.Uint64("rpcID", respID))
				}
			}
		}()
	})
}

// Call makes an RPC call
func (c *Client) Call(ctx context.Context, service, method string, req any, resp any) error {
	// Ensure the dispatcher is running
	c.startDispatcher()

	rpcReqID := transport.GenerateRPCID()

	// Create a channel for this RPC call (buffered to avoid blocking dispatcher)
	responseChan := make(chan *responseData, 1)

	// Register the channel atomically
	c.responseChans.Store(rpcReqID, responseChan)

	// Ensure we unregister the channel when done
	defer c.responseChans.Delete(rpcReqID)

	// Serialize the request payload
	reqPayloadBytes, err := c.serializer.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Frame the request into binary format
	framedReq, err := c.frameRequest(service, method, reqPayloadBytes)
	if err != nil {
		return fmt.Errorf("failed to frame request: %w", err)
	}

	// Send the framed request
	if err := c.transport.Send(c.defaultAddr, rpcReqID, framedReq, packet.PacketTypeData); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Wait for the response with context support
	select {
	case <-ctx.Done():
		// Context cancelled - unregister immediately to avoid receiving response for cancelled call
		c.responseChans.Delete(rpcReqID)
		return ctx.Err()
	case respData := <-responseChan:
		if respData.err != nil {
			return respData.err
		}

		// Process the packet based on its type
		switch respData.packetType {
		case packet.PacketTypeData:
			return c.handleResponsePacket(respData.data, respData.rpcID, resp)
		case packet.PacketTypeError, packet.PacketTypeUnknown:
			return c.handleErrorPacket(string(respData.data), respData.packetType)
		default:
			return fmt.Errorf("unknown packet type: %d", respData.packetType)
		}
	}
}

// GetTransport returns the underlying transport for advanced operations
func (c *Client) GetTransport() *transport.TCPTransport {
	return c.transport
}

// Close stops the response dispatcher and closes the transport
func (c *Client) Close() error {
	// Stop the dispatcher
	close(c.stopDispatcher)
	c.dispatcherWg.Wait()

	// Notify all waiting calls that the client is closing
	closeErr := &responseData{err: fmt.Errorf("client closed")}
	c.responseChans.Range(func(key, value any) bool {
		rpcID := key.(uint64)
		ch := value.(chan *responseData)
		select {
		case ch <- closeErr:
		default:
		}
		c.responseChans.Delete(rpcID)
		return true
	})

	// Close the transport
	return c.transport.Close()
}
