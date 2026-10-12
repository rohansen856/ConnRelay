package transport

import "net"

// Pipe returns two in-memory connected Conns for tests and local tooling.
// aFP and bFP are the certificate fingerprints each side presents; each
// side's RemoteCertFP is what it observes of the other, which a test can make
// differ from the real value to simulate an interposed peer.
func Pipe(aFP, bFP, aSeesB, bSeesA string) (Conn, Conn) {
	x, y := net.Pipe()
	return NewStreamConn(x, "tls13", PathWSSRelay, aFP, aSeesB),
		NewStreamConn(y, "tls13", PathWSSRelay, bFP, bSeesA)
}
