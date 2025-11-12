package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/appnet-org/arpc-tcp/pkg/packet"
	"github.com/appnet-org/arpc-tcp/pkg/transport/balancer"
	"github.com/appnet-org/arpc/pkg/logging"
	"go.uber.org/zap"
)

// GenerateRPCID creates a unique RPC ID
func GenerateRPCID() uint64 {
	return uint64(time.Now().UnixNano())
}

type TCPTransport struct {
	listener    *net.TCPListener
	conn        *net.TCPConn
	connMutex   sync.Mutex
	reassembler *DataReassembler
	resolver    *balancer.Resolver
	isServer    bool
}

func NewTCPTransport(address string) (*TCPTransport, error) {
	return NewTCPTransportWithBalancer(address, balancer.DefaultResolver())
}

// NewTCPTransportWithBalancer creates a new TCP transport with a custom balancer
func NewTCPTransportWithBalancer(address string, resolver *balancer.Resolver) (*TCPTransport, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}

	transport := &TCPTransport{
		listener:    listener,
		conn:        nil,
		reassembler: NewDataReassembler(),
		resolver:    resolver,
		isServer:    true,
	}

	return transport, nil
}

// NewTCPClientTransport creates a TCP transport for client use
func NewTCPClientTransport() (*TCPTransport, error) {
	transport := &TCPTransport{
		listener:    nil,
		conn:        nil,
		reassembler: NewDataReassembler(),
		resolver:    balancer.DefaultResolver(),
		isServer:    false,
	}

	return transport, nil
}

// NewTCPTransportForConnection creates a TCP transport for a server connection
// This is used to create a transport instance for each client connection
func NewTCPTransportForConnection(conn *net.TCPConn, resolver *balancer.Resolver) *TCPTransport {
	return &TCPTransport{
		listener:    nil,
		conn:        conn,
		connMutex:   sync.Mutex{},
		reassembler: NewDataReassembler(),
		resolver:    resolver,
		isServer:    true,
	}
}

// ResolveTCPTarget resolves a TCP address string that may be an IP, FQDN, or empty.
// If it's empty or ":port", it binds to 0.0.0.0:<port>. For FQDNs, it uses the configured balancer
// to select an IP from the resolved addresses.
func ResolveTCPTarget(addr string) (*net.TCPAddr, error) {
	// Use default resolver for backward compatibility
	return balancer.DefaultResolver().ResolveTCPTarget(addr)
}

// connect ensures we have a TCP connection to the target address (client only)
func (t *TCPTransport) connect(addr string) error {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()

	// If we already have a connection, try to use it
	if t.conn != nil {
		// Check if connection is still alive by checking if we can set a deadline
		// This is a lightweight check without actually reading
		if err := t.conn.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
			// Connection is dead, close it
			t.conn.Close()
			t.conn = nil
		} else {
			// Connection seems alive, clear the deadline
			t.conn.SetReadDeadline(time.Time{})
			return nil
		}
	}

	// If we don't have a connection, create one
	tcpAddr, err := t.resolver.ResolveTCPTarget(addr)
	if err != nil {
		return err
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return err
	}
	t.conn = conn

	return nil
}

func (t *TCPTransport) Send(addr string, rpcID uint64, data []byte, packetTypeID packet.PacketTypeID) error {
	// For client mode, ensure we have a connection
	// For server mode, connection is already established
	if !t.isServer {
		if err := t.connect(addr); err != nil {
			return err
		}
	}

	// Ensure we have a connection
	t.connMutex.Lock()
	conn := t.conn
	t.connMutex.Unlock()
	if conn == nil {
		return fmt.Errorf("no connection available")
	}

	// Extract destination IP and port from the connection's remote address
	var dstIP [4]byte
	var dstPort uint16
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	if ip4 := remoteAddr.IP.To4(); ip4 != nil {
		copy(dstIP[:], ip4)
		dstPort = uint16(remoteAddr.Port)
	}

	// Get source IP and port from local address
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	var srcIP [4]byte
	if ip4 := localAddr.IP.To4(); ip4 != nil {
		copy(srcIP[:], ip4)
	}
	srcPort := uint16(localAddr.Port)

	// Fragment the data into multiple packets if needed
	// Note: TCP can handle larger payloads, but we keep fragmentation for consistency
	packets, err := t.reassembler.FragmentData(data, rpcID, packetTypeID, dstIP, dstPort, srcIP, srcPort)
	if err != nil {
		return err
	}

	// Iterate through each fragment and send it via the TCP connection
	for _, pkt := range packets {
		var packetData []byte

		// Serialize based on packet type
		switch p := pkt.(type) {
		case *packet.DataPacket:
			packetData, err = packet.SerializeDataPacket(p)
		case *packet.ErrorPacket:
			packetData, err = packet.SerializeErrorPacket(p)
		default:
			return fmt.Errorf("unknown packet type: %T", pkt)
		}

		if err != nil {
			return fmt.Errorf("failed to serialize packet: %w", err)
		}

		logging.Debug("Serialized packet", zap.Uint64("rpcID", rpcID))

		// Write packet length first (4 bytes) for TCP framing
		packetLen := uint32(len(packetData))
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, packetLen)
		if _, err := conn.Write(lenBuf); err != nil {
			return err
		}

		_, err = conn.Write(packetData)
		logging.Debug("Sent packet", zap.Uint64("rpcID", rpcID))
		if err != nil {
			return err
		}
	}

	return nil
}

// Receive takes a buffer size as input, read data from the TCP socket, and return
// the following information when receiving the complete data for an RPC message:
// * complete data for a message (if no message is complete, it will return nil)
// * original source address from connection (for responses)
// * RPC id
// * packet type
// * error
func (t *TCPTransport) Receive(bufferSize int) ([]byte, *net.TCPAddr, uint64, packet.PacketTypeID, error) {
	// For client, use the existing connection
	var conn *net.TCPConn
	if t.isServer {
		// Server should use AcceptConnection to get a connection
		// This method is for receiving on an already accepted connection
		if t.conn == nil {
			return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("no connection available for server receive")
		}
		conn = t.conn
	} else {
		// Client uses the established connection
		t.connMutex.Lock()
		conn = t.conn
		t.connMutex.Unlock()
		if conn == nil {
			return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("no connection established for client receive")
		}
	}

	// Read packet length first (4 bytes) for TCP framing
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, nil, 0, packet.PacketTypeUnknown, err
	}

	packetLen := binary.LittleEndian.Uint32(lenBuf)
	if packetLen > uint32(bufferSize) {
		return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("packet length %d exceeds buffer size %d", packetLen, bufferSize)
	}

	// Read the actual packet data
	buffer := make([]byte, packetLen)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		return nil, nil, 0, packet.PacketTypeUnknown, err
	}

	// Get the remote address
	addr := conn.RemoteAddr().(*net.TCPAddr)

	// Deserialize the received data
	pkt, packetTypeID, err := packet.DeserializePacket(buffer)
	if err != nil {
		return nil, nil, 0, packet.PacketTypeUnknown, err
	}

	// Handle different packet types based on their nature
	switch p := pkt.(type) {
	case *packet.DataPacket:
		return t.ReassembleDataPacket(p, addr, packetTypeID)
	case *packet.ErrorPacket:
		return []byte(p.ErrorMsg), addr, p.RPCID, packetTypeID, nil
	default:
		// Unknown packet type - return early with no data
		logging.Debug("Unknown packet type", zap.Uint8("packetTypeID", uint8(packetTypeID)))
		return nil, nil, 0, packetTypeID, nil
	}
}

// AcceptConnection accepts a new TCP connection (server only)
func (t *TCPTransport) AcceptConnection() (*net.TCPConn, error) {
	if !t.isServer || t.listener == nil {
		return nil, fmt.Errorf("AcceptConnection can only be called on a server transport")
	}
	return t.listener.AcceptTCP()
}

// ReassembleDataPacket processes data packets through the reassembly layer
func (t *TCPTransport) ReassembleDataPacket(pkt *packet.DataPacket, addr *net.TCPAddr, packetTypeID packet.PacketTypeID) ([]byte, *net.TCPAddr, uint64, packet.PacketTypeID, error) {
	// Process fragment through reassembly layer
	fullMessage, _, reassembledRPCID, isComplete := t.reassembler.ProcessFragment(pkt, addr)

	if isComplete {
		// For responses, return the original source address from packet headers (SrcIP:SrcPort)
		// This allows the server to send responses back to the original client
		// However, with TCP we typically use the connection address
		originalSrcAddr := &net.TCPAddr{
			IP:   net.IP(pkt.SrcIP[:]),
			Port: int(pkt.SrcPort),
		}
		return fullMessage, originalSrcAddr, reassembledRPCID, packetTypeID, nil
	}

	// Still waiting for more fragments
	return nil, nil, 0, packetTypeID, nil
}

// SetConnection sets the TCP connection for this transport (used by server after accepting)
func (t *TCPTransport) SetConnection(conn *net.TCPConn) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	t.conn = conn
}

func (t *TCPTransport) Close() error {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()

	var err error
	if t.conn != nil {
		err = t.conn.Close()
		t.conn = nil
	}

	if t.listener != nil {
		listenerErr := t.listener.Close()
		if err == nil {
			err = listenerErr
		}
		t.listener = nil
	}

	return err
}

// GetConn returns the underlying TCP connection for direct packet sending
func (t *TCPTransport) GetConn() *net.TCPConn {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	return t.conn
}

// LocalAddr returns the local TCP address of the transport
func (t *TCPTransport) LocalAddr() *net.TCPAddr {
	if t.listener != nil {
		return t.listener.Addr().(*net.TCPAddr)
	}
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.conn != nil {
		return t.conn.LocalAddr().(*net.TCPAddr)
	}
	return nil
}

// GetResolver returns the resolver for this transport
func (t *TCPTransport) GetResolver() *balancer.Resolver {
	return t.resolver
}
