module github.com/appnet-org/proxy-tcp-transparent

go 1.24.0

require (
	github.com/appnet-org/arpc-tcp v0.0.0-20251031194350-0baf524417c5
	go.uber.org/zap v1.27.0
	golang.org/x/sys v0.38.0
)

require go.uber.org/multierr v1.11.0 // indirect

replace github.com/appnet-org/arpc-tcp => ../
