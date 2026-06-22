module github.com/rohansen856/connrelay/services/control

go 1.26.0

toolchain go1.27.2

require (
	github.com/coder/websocket v1.8.15
	github.com/rohansen856/connrelay/core/prwcore v0.0.0
	golang.org/x/time v0.15.0
)

require github.com/gowebpki/jcs v1.0.2 // indirect

replace github.com/rohansen856/connrelay/core/prwcore => ../../core/prwcore
