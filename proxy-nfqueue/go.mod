module github.com/appnet-org/proxy-nfqueue

go 1.24.0

require (
	github.com/appnet-org/arpc-tcp v0.0.0-20251031194350-0baf524417c5
	github.com/florianl/go-nfqueue/v2 v2.0.2
	github.com/mdlayher/netlink v1.8.0
	go.uber.org/zap v1.27.0
	golang.org/x/sys v0.38.0
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
)

replace github.com/appnet-org/arpc-tcp => ../
