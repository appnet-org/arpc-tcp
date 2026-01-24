package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/appnet-org/arpc-tcp/pkg/logging"
	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

type copyMode uint8

const (
	copyModeNone copyMode = iota
	copyModeMeta
	copyModePacket
)

type config struct {
	queueNum     uint16
	maxQueueLen  uint32
	maxPacketLen uint32
	copyMode     copyMode
	logFiveTuple bool
	afFamily     uint8
	failOpen     bool
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func main() {
	cfg := parseFlags()

	if err := logging.Init(getLoggingConfig()); err != nil {
		panic(fmt.Sprintf("Failed to initialize logging: %v", err))
	}

	logger := logging.GetLogger()
	logger.Info("Starting NFQUEUE proxy",
		zap.Uint16("queue", cfg.queueNum),
		zap.Uint32("max_queue_len", cfg.maxQueueLen),
		zap.Uint32("max_packet_len", cfg.maxPacketLen),
		zap.String("copy_mode", copyModeString(cfg.copyMode)),
		zap.Bool("log_5tuple", cfg.logFiveTuple),
		zap.Uint8("af_family", cfg.afFamily),
		zap.Bool("fail_open", cfg.failOpen))

	nfq, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      cfg.queueNum,
		MaxPacketLen: cfg.maxPacketLen,
		MaxQueueLen:  cfg.maxQueueLen,
		Copymode:     mapCopyMode(cfg.copyMode),
		Flags:        mapFailOpen(cfg.failOpen),
		AfFamily:     cfg.afFamily,
		ReadTimeout:  cfg.readTimeout,
		WriteTimeout: cfg.writeTimeout,
	})
	if err != nil {
		logger.Fatal("Failed to open NFQUEUE", zap.Error(err))
	}
	defer nfq.Close()

	if err := nfq.SetOption(netlink.NoENOBUFS, true); err != nil {
		logger.Warn("Failed to set NoENOBUFS option", zap.Error(err))
	}

	var packetCount atomic.Uint64
	var errorCount atomic.Uint64

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handleSignal(cancel)

	err = nfq.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		return handlePacket(logger, nfq, cfg, &packetCount, &errorCount, a)
	}, func(e error) int {
		errorCount.Add(1)
		if !errors.Is(e, nfqueue.ErrRecvMsg) {
			logger.Warn("NFQUEUE error", zap.Error(e))
		}
		return 0
	})
	if err != nil {
		logger.Fatal("Failed to register NFQUEUE handler", zap.Error(err))
	}

	<-ctx.Done()
	logger.Info("NFQUEUE proxy stopped")
}

func parseFlags() config {
	queueNum := flag.Uint("queue-num", 100, "NFQUEUE number")
	maxQueueLen := flag.Uint("max-queue-len", 4096, "Maximum packets in queue")
	maxPacketLen := flag.Uint("max-packet-len", 0xffff, "Maximum packet length to copy")
	copyModeFlag := flag.String("copymode", "packet", "Copy mode: packet|meta|none")
	logFiveTuple := flag.Bool("log-5tuple", false, "Log best-effort 5-tuple for packets")
	afFamily := flag.String("af-family", "unspec", "AF family: unspec|inet|inet6")
	failOpen := flag.Bool("fail-open", true, "Enable NFQUEUE fail-open")
	readTimeout := flag.Duration("read-timeout", 0, "Read timeout for NFQUEUE socket")
	writeTimeout := flag.Duration("write-timeout", 15*time.Millisecond, "Write timeout for NFQUEUE socket")
	flag.Parse()

	return config{
		queueNum:     uint16(*queueNum),
		maxQueueLen:  uint32(*maxQueueLen),
		maxPacketLen: uint32(*maxPacketLen),
		copyMode:     parseCopyMode(*copyModeFlag),
		logFiveTuple: *logFiveTuple,
		afFamily:     parseAfFamily(*afFamily),
		failOpen:     *failOpen,
		readTimeout:  *readTimeout,
		writeTimeout: *writeTimeout,
	}
}

func handlePacket(logger *zap.Logger, nfq *nfqueue.Nfqueue, cfg config, packetCount *atomic.Uint64, errorCount *atomic.Uint64, attr nfqueue.Attribute) int {
	if attr.PacketID == nil {
		errorCount.Add(1)
		return 0
	}

	total := packetCount.Add(1)

	var fields []zap.Field
	fields = append(fields, zap.Uint32("id", *attr.PacketID))
	fields = append(fields, zap.Uint64("total", total))
	if attr.Payload != nil {
		fields = append(fields, zap.Int("len", len(*attr.Payload)))
		if cfg.logFiveTuple {
			if tuple := formatFiveTuple(*attr.Payload); tuple != "" {
				fields = append(fields, zap.String("tuple", tuple))
			}
		}
	}
	logger.Debug("NFQUEUE packet", fields...)

	if err := nfq.SetVerdict(*attr.PacketID, nfqueue.NfAccept); err != nil {
		errorCount.Add(1)
		logger.Warn("Failed to set verdict", zap.Error(err))
	}

	return 0
}

func mapCopyMode(mode copyMode) uint8 {
	switch mode {
	case copyModeNone:
		return nfqueue.NfQnlCopyNone
	case copyModeMeta:
		return nfqueue.NfQnlCopyMeta
	default:
		return nfqueue.NfQnlCopyPacket
	}
}

func parseCopyMode(raw string) copyMode {
	switch strings.ToLower(raw) {
	case "none":
		return copyModeNone
	case "meta":
		return copyModeMeta
	default:
		return copyModePacket
	}
}

func copyModeString(mode copyMode) string {
	switch mode {
	case copyModeNone:
		return "none"
	case copyModeMeta:
		return "meta"
	default:
		return "packet"
	}
}

func mapFailOpen(enabled bool) uint32 {
	if enabled {
		return nfqueue.NfQaCfgFlagFailOpen
	}
	return 0
}

func parseAfFamily(raw string) uint8 {
	switch strings.ToLower(raw) {
	case "inet":
		return unix.AF_INET
	case "inet6":
		return unix.AF_INET6
	default:
		return 0
	}
}

func handleSignal(cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()
}

func formatFiveTuple(payload []byte) string {
	if len(payload) < 1 {
		return ""
	}

	version := payload[0] >> 4
	switch version {
	case 4:
		return formatIPv4Tuple(payload)
	case 6:
		return formatIPv6Tuple(payload)
	default:
		return ""
	}
}

func formatIPv4Tuple(payload []byte) string {
	if len(payload) < 20 {
		return ""
	}

	ihl := int(payload[0]&0x0f) * 4
	if len(payload) < ihl+4 {
		return ""
	}

	protocol := payload[9]
	srcIP := net.IP(payload[12:16]).String()
	dstIP := net.IP(payload[16:20]).String()

	if protocol != 6 && protocol != 17 {
		return fmt.Sprintf("ip4 proto=%d %s -> %s", protocol, srcIP, dstIP)
	}

	srcPort := uint16(payload[ihl])<<8 | uint16(payload[ihl+1])
	dstPort := uint16(payload[ihl+2])<<8 | uint16(payload[ihl+3])
	return fmt.Sprintf("%s %s:%d -> %s:%d", protocolLabel(protocol), srcIP, srcPort, dstIP, dstPort)
}

func formatIPv6Tuple(payload []byte) string {
	if len(payload) < 40 {
		return ""
	}

	nextHeader := payload[6]
	srcIP := net.IP(payload[8:24]).String()
	dstIP := net.IP(payload[24:40]).String()

	if nextHeader != 6 && nextHeader != 17 {
		return fmt.Sprintf("ip6 proto=%d %s -> %s", nextHeader, srcIP, dstIP)
	}

	if len(payload) < 44 {
		return ""
	}
	srcPort := uint16(payload[40])<<8 | uint16(payload[41])
	dstPort := uint16(payload[42])<<8 | uint16(payload[43])
	return fmt.Sprintf("%s %s:%d -> %s:%d", protocolLabel(nextHeader), srcIP, srcPort, dstIP, dstPort)
}

func protocolLabel(proto byte) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("proto-%d", proto)
	}
}

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
