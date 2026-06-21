package termserver

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/core/prwcore/peer"
	"github.com/rohansen856/connrelay/core/prwcore/transport"
	"github.com/rohansen856/connrelay/core/prwcore/transport/webrtc"
)

type identities struct {
	phone, host *attest.SoftwareSigner
}

// webrtcPair connects two in-process Pion peers over loopback.
func webrtcPair(t *testing.T) (transport.Conn, transport.Conn) {
	t.Helper()
	toHost := make(chan webrtc.Signal, 256)
	toPhone := make(chan webrtc.Signal, 256)
	ph, err := webrtc.NewPeer(webrtc.Config{Offerer: true, IncludeLoopback: true, UDPOnly: true, OnSignal: func(s webrtc.Signal) { toHost <- s }})
	if err != nil {
		t.Fatal(err)
	}
	hp, err := webrtc.NewPeer(webrtc.Config{IncludeLoopback: true, UDPOnly: true, OnSignal: func(s webrtc.Signal) { toPhone <- s }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	pump := func(ch chan webrtc.Signal, p *webrtc.Peer) {
		for {
			select {
			case s := <-ch:
				_ = p.HandleSignal(s)
			case <-ctx.Done():
				return
			}
		}
	}
	go pump(toHost, hp)
	go pump(toPhone, ph)
	if err := ph.Start(); err != nil {
		t.Fatal(err)
	}
	hc := make(chan transport.Conn, 1)
	go func() {
		c, err := hp.Wait(ctx)
		if err != nil {
			t.Error(err)
		}
		hc <- c
	}()
	pc, err := ph.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return pc, <-hc
}

// handshake runs mutual attestation on both ends of a fresh transport.
func handshake(t *testing.T, ids identities, attempt string, pc, hc transport.Conn) {
	t.Helper()
	ppub, _ := attest.ParsePublicKey(ids.phone.PublicKeySPKI())
	hpub, _ := attest.ParsePublicKey(ids.host.PublicKeySPKI())
	common := peer.Params{Attempt: attempt, Nonce: "n-" + attempt, Cap: "terminal", Impl: "e2e"}
	pp, hp := common, common
	pp.Role, pp.Self, pp.Peer, pp.Signer, pp.PeerKey, pp.Ticket = peer.RolePhone, "phone-1", "host-1", ids.phone, hpub, "ticket-"+attempt
	hp.Role, hp.Self, hp.Peer, hp.Signer, hp.PeerKey = peer.RoleHost, "host-1", "phone-1", ids.host, ppub
	hp.CheckTicket = func(tk string) ([]string, error) { return []string{"terminal"}, nil }
	errc := make(chan error, 1)
	go func() { _, err := peer.Handshake(context.Background(), hc, hp); errc <- err }()
	if _, err := peer.Handshake(context.Background(), pc, pp); err != nil {
		t.Fatalf("phone handshake: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("host handshake: %v", err)
	}
}

// TestEndToEndOverWebRTC: DTLS transport + attestation + tmux terminal, then
// a completely new WebRTC connection re-attaches to the same running shell.
func TestEndToEndOverWebRTC(t *testing.T) {
	s := newServer(t, 20)
	ph, _ := attest.NewSoftwareSigner()
	ho, _ := attest.NewSoftwareSigner()
	ids := identities{ph, ho}

	pc, hc := webrtcPair(t)
	handshake(t, ids, "att-1", pc, hc)
	go s.Serve(context.Background(), hc)
	p := newPhone(t, pc)
	if pc.Path() != transport.PathDirect || pc.Transport() != "dtls" {
		t.Fatalf("path %s transport %s", pc.Path(), pc.Transport())
	}
	r := p.open(100, 30)
	p.typeText(r.StreamID, "SECRET=over-dtls; echo PID=$$\r")
	pid := p.waitOutput(r.StreamID, regexp.MustCompile(`PID=(\d+)`))[1]
	p.drop() // the phone's transport dies (network switch, app killed)

	pc2, hc2 := webrtcPair(t)
	handshake(t, ids, "att-2", pc2, hc2) // fresh attempt, fresh DTLS, attestation again
	go s.Serve(context.Background(), hc2)
	q := newPhone(t, pc2)
	defer q.drop()
	r2 := q.attach(r.SessionID)
	q.typeText(r2.StreamID, "echo AGAIN=$$:$SECRET\r")
	m := q.waitOutput(r2.StreamID, regexp.MustCompile(`AGAIN=(\d+):([\w-]+)`))
	if m[1] != pid || m[2] != "over-dtls" {
		t.Fatalf("new connection reached a different shell: pid %s vs %s, %q", m[1], pid, m[2])
	}
}
