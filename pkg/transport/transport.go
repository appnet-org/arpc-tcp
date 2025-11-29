package transport

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
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

// isTLSEnabled checks if TLS is enabled via environment variable
func isTLSEnabled() bool {
	enabled := os.Getenv("ARPC_TLS_ENABLED")
	return enabled == "true" || enabled == "1" || enabled == "yes"
}

// loadTLSConfig loads TLS configuration from environment variables
// For server: ARPC_TLS_CERT_FILE and ARPC_TLS_KEY_FILE
// For mTLS server: ARPC_TLS_CA_FILE (required to verify client certificates)
// For client: ARPC_TLS_CA_FILE (optional, for custom CA)
// For mTLS client: ARPC_TLS_CLIENT_CERT_FILE and ARPC_TLS_CLIENT_KEY_FILE
// If ARPC_TLS_SKIP_VERIFY is set, client will skip certificate verification
func loadTLSConfig(isServer bool) (*tls.Config, error) {
	config := &tls.Config{}

	if isServer {
		certFile := os.Getenv("ARPC_TLS_CERT_FILE")
		keyFile := os.Getenv("ARPC_TLS_KEY_FILE")

		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("TLS enabled but ARPC_TLS_CERT_FILE or ARPC_TLS_KEY_FILE not set")
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		config.Certificates = []tls.Certificate{cert}

		// mTLS: Configure client certificate verification
		caFile := os.Getenv("ARPC_TLS_CA_FILE")
		if caFile != "" {
			caCert, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA certificate for client verification: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate for client verification")
			}

			config.ClientCAs = caCertPool
			config.ClientAuth = tls.RequireAndVerifyClientCert
		}
	} else {
		// Client configuration
		caFile := os.Getenv("ARPC_TLS_CA_FILE")
		skipVerify := os.Getenv("ARPC_TLS_SKIP_VERIFY") == "true" || os.Getenv("ARPC_TLS_SKIP_VERIFY") == "1"

		if caFile != "" {
			caCert, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA certificate: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}

			config.RootCAs = caCertPool
		}

		if skipVerify {
			config.InsecureSkipVerify = true
		}

		// mTLS: Load client certificate for mutual authentication
		clientCertFile := os.Getenv("ARPC_TLS_CLIENT_CERT_FILE")
		clientKeyFile := os.Getenv("ARPC_TLS_CLIENT_KEY_FILE")

		if clientCertFile != "" && clientKeyFile != "" {
			clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}

			config.Certificates = []tls.Certificate{clientCert}
		}
	}

	return config, nil
}

type TCPTransport struct {
	listener    net.Listener
	conn        net.Conn
	connMutex   sync.Mutex
	reassembler *DataReassembler
	resolver    *balancer.Resolver
	isServer    bool
	tlsConfig   *tls.Config
	tlsEnabled  bool
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

	tlsEnabled := isTLSEnabled()
	var listener net.Listener
	var tlsConfig *tls.Config

	if tlsEnabled {
		tlsConfig, err = loadTLSConfig(true)
		if err != nil {
			return nil, err
		}
		listener, err = tls.Listen("tcp", address, tlsConfig)
		if err != nil {
			return nil, err
		}
	} else {
		listener, err = net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			return nil, err
		}
	}

	transport := &TCPTransport{
		listener:    listener,
		conn:        nil,
		reassembler: NewDataReassembler(),
		resolver:    resolver,
		isServer:    true,
		tlsConfig:   tlsConfig,
		tlsEnabled:  tlsEnabled,
	}

	if tlsEnabled {
		logging.Info("TLS enabled for server", zap.String("address", address))
	} else {
		logging.Info("TLS disabled for server", zap.String("address", address))
	}

	return transport, nil
}

// NewTCPClientTransport creates a TCP transport for client use
func NewTCPClientTransport() (*TCPTransport, error) {
	tlsEnabled := isTLSEnabled()
	var tlsConfig *tls.Config
	var err error

	if tlsEnabled {
		tlsConfig, err = loadTLSConfig(false)
		if err != nil {
			return nil, err
		}
	}

	transport := &TCPTransport{
		listener:    nil,
		conn:        nil,
		reassembler: NewDataReassembler(),
		resolver:    balancer.DefaultResolver(),
		isServer:    false,
		tlsConfig:   tlsConfig,
		tlsEnabled:  tlsEnabled,
	}

	if tlsEnabled {
		logging.Info("TLS enabled for client")
	} else {
		logging.Info("TLS disabled for client")
	}

	return transport, nil
}

// NewTCPTransportForConnection creates a TCP transport for a server connection
// This is used to create a transport instance for each client connection
// If TLS is enabled, the connection should already be wrapped with TLS
func NewTCPTransportForConnection(conn net.Conn, resolver *balancer.Resolver) *TCPTransport {
	return &TCPTransport{
		listener:    nil,
		conn:        conn,
		connMutex:   sync.Mutex{},
		reassembler: NewDataReassembler(),
		resolver:    resolver,
		isServer:    true,
		tlsEnabled:  isTLSEnabled(),
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

	var conn net.Conn
	if t.tlsEnabled {
		// Create a copy of the TLS config with ServerName set from the address
		tlsConfig := t.tlsConfig.Clone()
		// Only set ServerName if InsecureSkipVerify is false and ServerName is not already set
		if !tlsConfig.InsecureSkipVerify && tlsConfig.ServerName == "" {
			// Extract hostname from address (format: hostname:port or ip:port)
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				// If parsing fails, try using the address as-is (might be just hostname)
				host = addr
			}
			// If host is empty (e.g., address was ":port"), default to localhost
			if host == "" {
				host = "localhost"
			}
			// Only set ServerName if it's not an IP address
			// For IP addresses, TLS requires either ServerName or InsecureSkipVerify
			if ip := net.ParseIP(host); ip == nil {
				// It's a hostname, set ServerName
				tlsConfig.ServerName = host
			} else {
				// For IP addresses, we need InsecureSkipVerify set
				// This is because Go's TLS requires explicit ServerName or InsecureSkipVerify
				// IP SAN verification will work, but we still need one of these set
				tlsConfig.InsecureSkipVerify = true
			}
		}
		conn, err = tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return err
		}
	} else {
		conn, err = net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			return err
		}
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
	remoteAddr := conn.RemoteAddr()
	var tcpAddr *net.TCPAddr
	var ok bool
	if tcpAddr, ok = remoteAddr.(*net.TCPAddr); !ok {
		// For TLS connections, try to resolve the address
		var err error
		tcpAddr, err = net.ResolveTCPAddr("tcp", remoteAddr.String())
		if err != nil {
			return fmt.Errorf("failed to resolve remote address: %w", err)
		}
	}
	if ip4 := tcpAddr.IP.To4(); ip4 != nil {
		copy(dstIP[:], ip4)
		dstPort = uint16(tcpAddr.Port)
	}

	// Get source IP and port from local address
	var srcIP [4]byte
	var srcPort uint16
	localAddr := conn.LocalAddr()
	var localTCPAddr *net.TCPAddr
	if localTCPAddr, ok = localAddr.(*net.TCPAddr); !ok {
		// For TLS connections, try to resolve the address
		var err error
		localTCPAddr, err = net.ResolveTCPAddr("tcp", localAddr.String())
		if err != nil {
			return fmt.Errorf("failed to resolve local address: %w", err)
		}
	}
	if ip4 := localTCPAddr.IP.To4(); ip4 != nil {
		copy(srcIP[:], ip4)
	}
	srcPort = uint16(localTCPAddr.Port)

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
	var conn net.Conn
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
	var addr *net.TCPAddr
	remoteAddr := conn.RemoteAddr()
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		addr = tcpAddr
	} else {
		// For TLS connections, try to extract TCP address
		host, port, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("failed to parse remote address: %w", err)
		}
		tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
		if err != nil {
			return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("failed to resolve remote address: %w", err)
		}
		addr = tcpAddr
	}

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
// If TLS is enabled, returns a TLS-wrapped connection
func (t *TCPTransport) AcceptConnection() (net.Conn, error) {
	if !t.isServer || t.listener == nil {
		return nil, fmt.Errorf("AcceptConnection can only be called on a server transport")
	}
	return t.listener.Accept()
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
// If TLS is enabled, the connection should already be wrapped with TLS
func (t *TCPTransport) SetConnection(conn net.Conn) {
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

// GetConn returns the underlying connection for direct packet sending
// May return a *net.TCPConn or *tls.Conn depending on TLS configuration
func (t *TCPTransport) GetConn() net.Conn {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	return t.conn
}

// LocalAddr returns the local TCP address of the transport
func (t *TCPTransport) LocalAddr() *net.TCPAddr {
	if t.listener != nil {
		addr := t.listener.Addr()
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			return tcpAddr
		}
		// For TLS listeners, try to resolve the address
		host, port, err := net.SplitHostPort(addr.String())
		if err == nil {
			tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
			if err == nil {
				return tcpAddr
			}
		}
		return nil
	}
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.conn != nil {
		addr := t.conn.LocalAddr()
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			return tcpAddr
		}
		// For TLS connections, try to resolve the address
		host, port, err := net.SplitHostPort(addr.String())
		if err == nil {
			tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
			if err == nil {
				return tcpAddr
			}
		}
	}
	return nil
}

// GetResolver returns the resolver for this transport
func (t *TCPTransport) GetResolver() *balancer.Resolver {
	return t.resolver
}
