package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/appnet-org/arpc-tcp/pkg/logging"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// Config holds the proxy configuration
type Config struct {
	Ports     []int
	Interface string // Network interface to bind to (empty = all)
}

// ProxyState manages the state of the transparent proxy
type ProxyState struct {
	// Connection counter for unique IDs
	connCounter uint64
	connMu      sync.Mutex
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

// getNextConnectionID generates a unique connection ID
func (s *ProxyState) getNextConnectionID() string {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.connCounter++
	return fmt.Sprintf("conn-%d", s.connCounter)
}

// getOriginalDestination retrieves the original destination address for a TPROXY connection
// With TPROXY and IP_TRANSPARENT, the LocalAddr() of the accepted connection
// is the original destination address
func getOriginalDestination(conn net.Conn) (string, error) {
	// With TPROXY, LocalAddr() returns the original destination
	localAddr := conn.LocalAddr()
	if localAddr == nil {
		return "", fmt.Errorf("no local address available")
	}
	return localAddr.String(), nil
}

// createTransparentListener creates a TCP listener with IP_TRANSPARENT for TPROXY
func createTransparentListener(port int) (net.Listener, error) {
	// Create socket manually to set IP_TRANSPARENT
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	// Enable IP_TRANSPARENT - this is required for TPROXY
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set IP_TRANSPARENT: %w", err)
	}

	// Enable receiving original destination address
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set IP_RECVORIGDSTADDR: %w", err)
	}

	// Reuse address and port
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set SO_REUSEADDR: %w", err)
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set SO_REUSEPORT: %w", err)
	}

	// Bind to the port (0.0.0.0:port)
	addr := &unix.SockaddrInet4{Port: port}
	copy(addr.Addr[:], net.IPv4zero.To4())
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to bind to port %d: %w", port, err)
	}

	// Listen on the socket
	if err := unix.Listen(fd, 128); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	// Convert to Go net.Listener
	file := os.NewFile(uintptr(fd), fmt.Sprintf("tproxy-%d", port))
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to create file from fd")
	}

	listener, err := net.FileListener(file)
	if err != nil {
		file.Close()
		unix.Close(fd)
		return nil, fmt.Errorf("failed to create listener from file: %w", err)
	}

	return listener, nil
}

// handleTransparentConnection handles a connection received via TPROXY
// With TPROXY, the connection is intercepted but we need to relay to the original destination
func handleTransparentConnection(conn net.Conn, state *ProxyState, port int) {
	defer conn.Close()

	// Get original destination (with TPROXY, LocalAddr() is the original destination)
	origDst, err := getOriginalDestination(conn)
	if err != nil {
		logging.GetLogger().Debug("Failed to get original destination", zap.Error(err))
		// Continue anyway - connection is still transparent
	}

	connID := state.getNextConnectionID()
	logging.GetLogger().Info("New transparent connection",
		zap.String("connID", connID),
		zap.String("clientAddr", conn.RemoteAddr().String()),
		zap.String("localAddr", conn.LocalAddr().String()),
		zap.String("originalDst", origDst),
		zap.Int("port", port))

	// With TPROXY, we intercept the connection from the client
	// We need to connect to the original destination and relay data
	if origDst == "" {
		logging.GetLogger().Warn("No original destination, cannot forward",
			zap.String("connID", connID))
		return
	}

	// Connect to the original destination
	// Note: This creates a new connection, but the client's connection is transparent
	// The client sees the original destination IP/port, not the proxy's
	targetConn, err := net.Dial("tcp", origDst)
	if err != nil {
		logging.GetLogger().Warn("Failed to connect to original destination",
			zap.String("connID", connID),
			zap.String("target", origDst),
			zap.Error(err))
		return
	}
	defer targetConn.Close()

	logging.GetLogger().Info("Connected to original destination",
		zap.String("connID", connID),
		zap.String("target", origDst))

	// Relay data bidirectionally
	// Since we're not inspecting data, we just copy it through
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		written, err := io.Copy(targetConn, conn)
		if err != nil {
			logging.GetLogger().Debug("Error copying client->target",
				zap.String("connID", connID),
				zap.Error(err))
		}
		logging.GetLogger().Debug("Finished copying client->target",
			zap.String("connID", connID),
			zap.Int64("bytes", written))
		targetConn.Close()
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		written, err := io.Copy(conn, targetConn)
		if err != nil {
			logging.GetLogger().Debug("Error copying target->client",
				zap.String("connID", connID),
				zap.Error(err))
		}
		logging.GetLogger().Debug("Finished copying target->client",
			zap.String("connID", connID),
			zap.Int64("bytes", written))
		conn.Close()
	}()

	wg.Wait()
	logging.GetLogger().Debug("Connection closed", zap.String("connID", connID))
}

// runTPROXYServer runs a TPROXY server on the specified port
func runTPROXYServer(port int, state *ProxyState) error {
	listener, err := createTransparentListener(port)
	if err != nil {
		return fmt.Errorf("failed to create transparent listener on port %d: %w", port, err)
	}
	defer listener.Close()

	logging.GetLogger().Info("Listening on transparent TPROXY port", zap.Int("port", port))

	for {
		conn, err := listener.Accept()
		if err != nil {
			logging.GetLogger().Error("Accept error", zap.Int("port", port), zap.Error(err))
			continue
		}

		go handleTransparentConnection(conn, state, port)
	}
}

// startTPROXYServers starts TPROXY listeners on the configured ports
func startTPROXYServers(config *Config, state *ProxyState) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(config.Ports))

	for _, port := range config.Ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if err := runTPROXYServer(p, state); err != nil {
				errCh <- fmt.Errorf("TPROXY server on port %d failed: %w", p, err)
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

// waitForShutdown waits for a shutdown signal
func waitForShutdown() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logging.GetLogger().Info("Shutting down transparent proxy...")
}

func main() {
	var (
		ports = flag.String("ports", "15002,15006", "Comma-separated list of ports to listen on")
		iface = flag.String("interface", "", "Network interface to bind to (empty = all, not used yet)")
	)
	flag.Parse()

	// Initialize logging
	err := logging.Init(getLoggingConfig())
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logging: %v", err))
	}

	// Parse ports
	portList := []int{15002, 15006} // defaults
	if *ports != "" && *ports != "15002,15006" {
		portList = []int{}
		parts := strings.Split(*ports, ",")
		for _, part := range parts {
			var p int
			if _, err := fmt.Sscanf(strings.TrimSpace(part), "%d", &p); err == nil {
				portList = append(portList, p)
			}
		}
		if len(portList) == 0 {
			portList = []int{15002, 15006}
		}
	}

	config := &Config{
		Ports:     portList,
		Interface: *iface,
	}

	logging.GetLogger().Info("Starting transparent TCP proxy (TPROXY)",
		zap.Ints("ports", config.Ports),
		zap.String("interface", config.Interface))

	state := &ProxyState{
		connCounter: 0,
	}

	// Start TPROXY servers
	if err := startTPROXYServers(config, state); err != nil {
		logging.GetLogger().Fatal("Failed to start TPROXY servers", zap.Error(err))
	}

	// Wait for shutdown signal
	waitForShutdown()
}

