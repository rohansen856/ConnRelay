// Package gocore only anchors the gomobile build of
// github.com/rohansen856/connrelay/core/connrelaycore/mobile for the app; see
// build-aar.sh. It is built outside the main Go workspace (GOWORK=off).
package gocore

import _ "github.com/rohansen856/connrelay/core/connrelaycore/mobile"
