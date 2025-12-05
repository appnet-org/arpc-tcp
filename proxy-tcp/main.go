package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"

	"github.com/appnet-org/arpc-tcp/pkg/logging"
	"github.com/appnet-org/arpc-tcp/pkg/transport"
	"github.com/appnet-org/proxy-tcp/element"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	// DefaultBufferSize is the size of the buffer used for reading data
	DefaultBufferSize = 4096
)

// ProxyState manages the state of the TCP proxy
type ProxyState struct {
	elementChain *element.RPCElementChain
	// Target server address for proxying (optional, can be configured via env)
	// Used only if SO_ORIGINAL_DST is unavailable
	targetAddr string
	// Connection counter for unique IDs
	connCounter uint64
	connMu      sync.Mutex
}

// Config holds the proxy configuration
type Config struct {
	Ports      []int
	TargetAddr string
	// TLS Configuration
	TLSEnabled     bool
	CertFile       string // Server cert for inbound (proxy acts as server)
	KeyFile        string // Server key for inbound
	CAFile         string // CA cert for mTLS (verify clients)
	ClientCertFile string // Client cert for outbound (proxy acts as client)
	ClientKeyFile  string // Client key for outbound
	TLSSkipVerify  bool   // Skip server certificate verification on outbound
	// Buffering Configuration
	BufferingEnabled bool
}

// DefaultConfig returns the default proxy configuration
func DefaultConfig() *Config {
	targetAddr := os.Getenv("TARGET_ADDR")
	if targetAddr == "" {
		targetAddr = "" // Empty by default - use iptables interception
	}

	return &Config{
		Ports:      []int{15002, 15006},
		TargetAddr: targetAddr,
	}
}

// getOriginalDestination retrieves the original destination address for a TCP connection
// that was redirected by iptables. Returns the address and true if available.
func getOriginalDestination(conn net.Conn) (string, bool) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", false
	}

	file, err := tcpConn.File()
	if err != nil {
		logging.Debug("Failed to get file from connection", zap.Error(err))
		return "", false
	}
	defer file.Close()

	fd := file.Fd()

	// Try to get the original destination using SO_ORIGINAL_DST
	// This socket option is set by iptables REDIRECT target
	return getOriginalDestinationIPv4(fd)
}

// getOriginalDestinationIPv4 retrieves the original destination for IPv4 connections
func getOriginalDestinationIPv4(fd uintptr) (string, bool) {
	// For IPv4, SO_ORIGINAL_DST returns a sockaddr_in structure
	// Size of sockaddr_in: family (2) + port (2) + addr (4) + zero padding (8) = 16 bytes
	var sockaddr [128]byte
	size := uint32(len(sockaddr))

	// SO_ORIGINAL_DST is at IPPROTO_IP level, not SOL_SOCKET
	// This socket option is set by iptables REDIRECT target
	err := getSockopt(int(fd), syscall.IPPROTO_IP, unix.SO_ORIGINAL_DST, unsafe.Pointer(&sockaddr[0]), &size)
	if err != nil {
		logging.Debug("Failed to get SO_ORIGINAL_DST", zap.Error(err))
		return "", false
	}

	// Parse sockaddr_in: [family(2)][port(2)][addr(4)][...]
	if size < 8 {
		return "", false
	}

	family := binary.LittleEndian.Uint16(sockaddr[0:2])
	if family != syscall.AF_INET {
		return "", false
	}

	port := binary.BigEndian.Uint16(sockaddr[2:4])
	ip := net.IPv4(sockaddr[4], sockaddr[5], sockaddr[6], sockaddr[7])

	return fmt.Sprintf("%s:%d", ip.String(), port), true
}

// getSockopt performs getsockopt syscall
func getSockopt(s, level, name int, val unsafe.Pointer, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(s),
		uintptr(level),
		uintptr(name),
		uintptr(val),
		uintptr(unsafe.Pointer(vallen)),
		0,
	)
	if e1 != 0 {
		err = e1
	}
	return
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

// loadCAPool loads CA certificates from a file into a cert pool
func loadCAPool(caFile string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return caPool, nil
}

// getNextConnectionID generates a unique connection ID
func (s *ProxyState) getNextConnectionID() string {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.connCounter++
	return fmt.Sprintf("conn-%d", s.connCounter)
}

func main() {
	var (
		enableMTLS        = flag.Bool("mtls", false, "Enable mutual TLS (requires CA and client cert/key for full mTLS support)")
		tlsEnabled        = flag.Bool("tls", false, "Enable TLS termination")
		tlsCertFile       = flag.String("tls-cert-file", "", "Server cert file (for decrypting incoming)")
		tlsKeyFile        = flag.String("tls-key-file", "", "Server key file (for decrypting incoming)")
		tlsCAFile         = flag.String("tls-ca-file", "", "CA cert file (for verifying client certs in mTLS)")
		tlsClientCertFile = flag.String("tls-client-cert-file", "", "Client cert file (for authenticating to upstream in mTLS)")
		tlsClientKeyFile  = flag.String("tls-client-key-file", "", "Client key file (for authenticating to upstream in mTLS)")
		tlsSkipVerify     = flag.Bool("tls-skip-verify", true, "Skip server certificate verification on outbound connections (insecure, for testing only)")
		bufferingEnabled  = flag.Bool("buffering", false, "Enable buffering mode (buffer packets until complete RPC message)")
	)
	flag.Parse()

	// Initialize logging
	err := logging.Init(getLoggingConfig())
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logging: %v", err))
	}

	// 2. Populate Config
	config := &Config{
		Ports:            []int{15002, 15006},
		TargetAddr:       os.Getenv("TARGET_ADDR"),
		TLSEnabled:       *tlsEnabled || *enableMTLS,
		CertFile:         *tlsCertFile,
		KeyFile:          *tlsKeyFile,
		CAFile:           *tlsCAFile,
		ClientCertFile:   *tlsClientCertFile,
		ClientKeyFile:    *tlsClientKeyFile,
		TLSSkipVerify:    *tlsSkipVerify,
		BufferingEnabled: *bufferingEnabled,
	}

	if config.TLSEnabled {
		if config.CertFile == "" || config.KeyFile == "" {
			logging.Fatal("TLS enabled but cert/key missing. Use -tls-cert-file and -tls-key-file")
		}

		isMTLS := config.CAFile != "" || (config.ClientCertFile != "" && config.ClientKeyFile != "")

		if isMTLS {
			logging.Info("mTLS Termination Enabled",
				zap.String("server_cert", config.CertFile),
				zap.String("server_key", config.KeyFile),
				zap.String("ca_file", config.CAFile),
				zap.String("client_cert", config.ClientCertFile),
				zap.String("client_key", config.ClientKeyFile),
				zap.Bool("skip_verify", config.TLSSkipVerify))
		} else {
			logging.Info("TLS Termination Enabled (one-way)",
				zap.String("cert", config.CertFile),
				zap.String("key", config.KeyFile),
				zap.Bool("skip_verify", config.TLSSkipVerify))
		}
	} else {
		logging.Info("TLS Termination DISABLED (Blind Forwarding)")
	}

	if config.BufferingEnabled {
		logging.Info("Buffering Mode ENABLED (Wait for complete RPC)")
	} else {
		logging.Info("Buffering Mode DISABLED (Streaming)")
	}

	logging.Info("Starting bidirectional TCP proxy on :15002 and :15006...")

	// Create element chain
	elementChain := element.NewRPCElementChain(
	// element.NewLoggingElement(true), // Enable verbose logging if needed
	)

	state := &ProxyState{
		elementChain: elementChain,
		targetAddr:   config.TargetAddr,
		connCounter:  0,
	}

	logging.Info("Proxy target configured", zap.String("target", state.targetAddr))

	// Start proxy servers
	if err := startProxyServers(config, state); err != nil {
		logging.Fatal("Failed to start proxy servers", zap.Error(err))
	}

	// Wait for shutdown signal
	waitForShutdown()
}

// startProxyServers starts TCP listeners on the configured ports
func startProxyServers(config *Config, state *ProxyState) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(config.Ports))

	for _, port := range config.Ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if err := runProxyServer(p, state, config); err != nil {
				errCh <- fmt.Errorf("proxy server on port %d failed: %w", p, err)
			}
		}(port)
	}

	// Wait for all servers to start or fail
	wg.Wait()
	close(errCh)

	// Check for any startup errors
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// runProxyServer runs a single TCP proxy server on the specified port
func runProxyServer(port int, state *ProxyState, config *Config) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on TCP port %d: %w", port, err)
	}
	defer listener.Close()

	logging.Info("Listening on TCP port", zap.Int("port", port))

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			logging.Error("Accept error", zap.Int("port", port), zap.Error(err))
			continue
		}

		go handleConnection(clientConn, state, config)
	}
}

// handleConnection processes a TCP connection and forwards traffic
func handleConnection(clientConn net.Conn, state *ProxyState, config *Config) {
	defer clientConn.Close()

	connID := state.getNextConnectionID()
	logging.Info("New TCP connection",
		zap.String("connID", connID),
		zap.String("clientAddr", clientConn.RemoteAddr().String()),
		zap.String("localAddr", clientConn.LocalAddr().String()))

	// 1. Get Original Destination (Always done on raw connection)
	targetAddr := state.targetAddr
	if origDst, ok := getOriginalDestination(clientConn); ok {
		targetAddr = origDst
		logging.Info("Using iptables original destination",
			zap.String("connID", connID),
			zap.String("original_dst", origDst),
			zap.String("clientAddr", clientConn.RemoteAddr().String()))
	} else if targetAddr == "" {
		logging.Error("No target address available (neither SO_ORIGINAL_DST nor TARGET_ADDR)",
			zap.String("connID", connID))
		return
	}

	// Define the abstract connections we will use
	var inboundConn net.Conn = clientConn
	var outboundConn net.Conn

	// 2. LOGIC SWITCH: TLS Termination vs Blind Forwarding
	if config.TLSEnabled {
		// --- MODE A: TLS TERMINATION (Decrypt -> Process -> Encrypt) ---

		// A. Upgrade Inbound (Client -> Proxy) to TLS Server
		serverCert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			logging.Error("Failed to load server certs", zap.Error(err))
			return
		}

		serverTLSConfig := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
		}

		// If CA file is provided, enable client certificate verification (mTLS)
		if config.CAFile != "" {
			caPool, err := loadCAPool(config.CAFile)
			if err != nil {
				logging.Error("Failed to load CA pool for client verification", zap.Error(err))
				return
			}
			serverTLSConfig.ClientCAs = caPool
			serverTLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			logging.Debug("Inbound mTLS: client cert verification enabled", zap.String("connID", connID))
		}

		inboundConn = tls.Server(clientConn, serverTLSConfig)

		// B. Connect Outbound (Proxy -> Target) as TLS Client
		clientTLSConfig := &tls.Config{
			InsecureSkipVerify: config.TLSSkipVerify,
		}

		// If client cert/key are provided, present them for mTLS authentication
		if config.ClientCertFile != "" && config.ClientKeyFile != "" {
			clientCert, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
			if err != nil {
				logging.Error("Failed to load client certs for outbound", zap.Error(err))
				return
			}
			clientTLSConfig.Certificates = []tls.Certificate{clientCert}
			logging.Debug("Outbound mTLS: presenting client cert", zap.String("connID", connID))
		}

		outboundConn, err = tls.Dial("tcp", targetAddr, clientTLSConfig)
		if err != nil {
			logging.Warn("Failed to connect to target (TLS)", zap.Error(err))
			return
		}

		logging.Info("Proxying with TLS Termination (Plaintext inspection active)", zap.String("connID", connID))

	} else {
		// --- MODE B: BLIND FORWARDING (Forward Raw Bytes) ---
		// If app uses TLS, these bytes will be encrypted "garbage"

		var err error
		outboundConn, err = net.Dial("tcp", targetAddr)
		if err != nil {
			logging.Warn("Failed to connect to target (TCP)", zap.Error(err))
			return
		}

		logging.Info("Proxying Raw TCP (Blind Forwarding)", zap.String("connID", connID))
	}

	defer outboundConn.Close()

	// 3. Start Bi-directional Stream
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		handleTCPStream(inboundConn, outboundConn, state, ctx, true, connID, targetAddr, config.BufferingEnabled)
	}()

	go func() {
		defer wg.Done()
		handleTCPStream(outboundConn, inboundConn, state, ctx, false, connID, targetAddr, config.BufferingEnabled)
	}()

	wg.Wait()
	logging.Debug("Connection closed", zap.String("connID", connID))
}

// processDataThroughElementChain processes data through the element chain
// Returns verdict and whether the data should be forwarded (false if dropped)
func processDataThroughElementChain(ctx context.Context, state *ProxyState, connID string, data []byte, isRequest bool, remoteAddr, targetAddr string) (element.Verdict, []byte, bool) {
	// Create a copy of the data for processing
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	// Create TCPRPCContext for element chain processing
	rpcCtx := &element.TCPRPCContext{
		Data:         dataCopy,
		ConnectionID: connID,
		IsRequest:    isRequest,
		RemoteAddr:   remoteAddr,
		TargetAddr:   targetAddr,
	}

	// Process through element chain
	var verdict element.Verdict
	var err error
	if isRequest {
		verdict, _, err = state.elementChain.ProcessRequest(ctx, rpcCtx)
	} else {
		verdict, _, err = state.elementChain.ProcessResponse(ctx, rpcCtx)
	}

	if err != nil {
		logging.Error("Error processing data through element chain",
			zap.String("connID", connID),
			zap.Bool("isRequest", isRequest),
			zap.Error(err))
		// On error, pass through (don't drop)
		return element.VerdictPass, data, true
	}

	if verdict == element.VerdictDrop {
		logging.Debug("Data dropped by element chain",
			zap.String("connID", connID),
			zap.Bool("isRequest", isRequest),
			zap.String("verdict", verdict.String()))
		return element.VerdictDrop, nil, false
	}

	// Return the potentially modified data
	return element.VerdictPass, rpcCtx.Data, true
}

// handleTCPStream processes TCP data in one direction
func handleTCPStream(srcConn net.Conn, dstConn net.Conn, state *ProxyState, ctx context.Context, isRequest bool, connID, targetAddr string, buffering bool) {
	if buffering {
		handleBufferedTCPStream(srcConn, dstConn, state, ctx, isRequest, connID, targetAddr)
		return
	}

	buffer := make([]byte, DefaultBufferSize)
	direction := "request"
	if !isRequest {
		direction = "response"
	}

	for {
		n, err := srcConn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				logging.Debug("Read error",
					zap.String("connID", connID),
					zap.String("direction", direction),
					zap.Error(err))
			}
			return
		}

		if n == 0 {
			continue
		}

		data := buffer[:n]
		logging.Debug("Received TCP data",
			zap.String("connID", connID),
			zap.String("direction", direction),
			zap.Int("dataLen", n),
			zap.String("payload", string(data)))

		// Process through element chain
		verdict, processedData, shouldForward := processDataThroughElementChain(
			ctx, state, connID, data, isRequest,
			srcConn.RemoteAddr().String(), targetAddr)

		if !shouldForward {
			// Data was dropped by element chain
			logging.Debug("Data dropped, not forwarding",
				zap.String("connID", connID),
				zap.String("direction", direction),
				zap.String("verdict", verdict.String()))
			continue
		}

		// Forward processed data to destination
		if len(processedData) > 0 {
			written, err := dstConn.Write(processedData)
			if err != nil {
				logging.Error("Write error",
					zap.String("connID", connID),
					zap.String("direction", direction),
					zap.Error(err))
				return
			}
			if written != len(processedData) {
				logging.Warn("Partial write",
					zap.String("connID", connID),
					zap.String("direction", direction),
					zap.Int("expected", len(processedData)),
					zap.Int("written", written))
			}
			logging.Debug("Forwarded TCP data",
				zap.String("connID", connID),
				zap.String("direction", direction),
				zap.Int("dataLen", len(processedData)),
				zap.String("payload", string(processedData)))
		}
	}
}

// handleBufferedTCPStream processes TCP data in buffering mode (waiting for full RPC)
func handleBufferedTCPStream(srcConn net.Conn, dstConn net.Conn, state *ProxyState, ctx context.Context, isRequest bool, connID, targetAddr string) {
	direction := "request"
	if !isRequest {
		direction = "response"
	}

	// Create TCPTransports to handle the framing, reassembly, and fragmentation
	// We use NewTCPTransportForConnection to wrap existing connections (acting as Server mode to avoid dial)
	// For logging/logic purposes:
	// - srcTrans receives data from srcConn
	// - dstTrans sends data to dstConn
	srcTrans := transport.NewTCPTransportForConnection(srcConn, nil)
	dstTrans := transport.NewTCPTransportForConnection(dstConn, nil)

	// Ensure transports are closed when function exits
	defer srcTrans.Close()
	defer dstTrans.Close()

	// Use a large enough buffer for receiving packets
	// 65536 covers MaxTCPPayloadSize + headers
	const ReceiveBufferSize = 65536

	for {
		// Receive attempts to read a packet and reassemble fragments
		// It returns data only when a complete RPC message is available (or an error packet)
		data, _, rpcID, pktType, err := srcTrans.Receive(ReceiveBufferSize)
		if err != nil {
			if err != io.EOF {
				logging.Debug("Receive error",
					zap.String("connID", connID),
					zap.String("direction", direction),
					zap.Error(err))
			}
			return
		}

		// If data is nil, it means we processed a fragment but still waiting for more.
		// Continue loop.
		if data == nil {
			continue
		}

		logging.Debug("Received Complete RPC Message",
			zap.String("connID", connID),
			zap.String("direction", direction),
			zap.Uint64("rpcID", rpcID),
			zap.Int("dataLen", len(data)))

		// Process complete RPC message through element chain
		verdict, processedData, shouldForward := processDataThroughElementChain(
			ctx, state, connID, data, isRequest,
			srcConn.RemoteAddr().String(), targetAddr)

		if !shouldForward {
			logging.Debug("RPC Message dropped by element chain",
				zap.String("connID", connID),
				zap.String("direction", direction),
				zap.Uint64("rpcID", rpcID),
				zap.String("verdict", verdict.String()))
			continue
		}

		// Send the processed message
		// This handles fragmentation automatically inside transport.Send
		// We pass targetAddr string, though strictly it's ignored because dstTrans is in Server mode (has conn)
		if err := dstTrans.Send(targetAddr, rpcID, processedData, pktType); err != nil {
			logging.Error("Send error",
				zap.String("connID", connID),
				zap.String("direction", direction),
				zap.Uint64("rpcID", rpcID),
				zap.Error(err))
			return
		}

		logging.Debug("Forwarded RPC Message",
			zap.String("connID", connID),
			zap.String("direction", direction),
			zap.Uint64("rpcID", rpcID),
			zap.Int("dataLen", len(processedData)))
	}
}

// waitForShutdown waits for a shutdown signal
func waitForShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logging.Info("Shutting down proxy...")
}
