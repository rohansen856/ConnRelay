package pairclient

import (
	"strings"

	"rsc.io/qr"
)

// RenderQR draws a QR code with Unicode half blocks (two modules per
// character row), with a quiet zone, for display in a terminal.
func RenderQR(payload string) (string, error) {
	code, err := qr.Encode(payload, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 2
	n := code.Size
	black := func(x, y int) bool {
		if x < 0 || y < 0 || x >= n || y >= n {
			return false
		}
		return code.Black(x, y)
	}
	var b strings.Builder
	for y := -quiet; y < n+quiet; y += 2 {
		for x := -quiet; x < n+quiet; x++ {
			top, bottom := black(x, y), black(x, y+1)
			// Light modules are drawn as blocks so the code reads on dark terminals.
			switch {
			case !top && !bottom:
				b.WriteRune('█')
			case !top && bottom:
				b.WriteRune('▀')
			case top && !bottom:
				b.WriteRune('▄')
			default:
				b.WriteRune(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}
