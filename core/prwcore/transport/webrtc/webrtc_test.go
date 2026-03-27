package webrtc

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/turn/v4"
	"github.com/pion/webrtc/v4"
	"github.com/rohansen856/connrelay/core/prwcore/frame"
	"github.com/rohansen856/connrelay/core/prwcore/transport"
)

// pair wires two peers together with in-memory signaling.
func pair(t *testing.T, base Config) (transport.Conn, transport.Conn) {
	t.Helper()
	var offerer, answerer *Peer
	toAns := make(chan Signal, 256)
	toOff := make(chan Signal, 256)
	oc, ac := base, base
	oc.Offerer, ac.Offerer = true, false
	oc.OnSignal = func(s Signal) { toAns <- s }
	ac.OnSignal = func(s Signal) { toOff <- s }
	var err error
	if offerer, err = NewPeer(oc); err != nil {
		t.Fatal(err)
	}
	if answerer, err = NewPeer(ac); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	pump := func(ch chan Signal, p *Peer) {
		for {
			select {
			case s := <-ch:
				if err := p.HandleSignal(s); err != nil {
					t.Errorf("signal %s: %v", s.Type, err)
				}
			case <-ctx.Done():
				return
			}
		}
	}
	go pump(toAns, answerer)
	go pump(toOff, offerer)
	if err := offerer.Start(); err != nil {
		t.Fatal(err)
	}
	type res struct {
		c   transport.Conn
		err error
	}
	ach := make(chan res, 1)
	go func() { c, err := answerer.Wait(ctx); ach <- res{c, err} }()
	phone, err := offerer.Wait(ctx)
	if err != nil {
		t.Fatalf("offerer: %v", err)
	}
	r := <-ach
	if r.err != nil {
		t.Fatalf("answerer: %v", r.err)
	}
	t.Cleanup(func() { phone.Close(); r.c.Close() })
	return phone, r.c
}

func exchange(t *testing.T, phone, host transport.Conn) {
	t.Helper()
	if err := phone.Send(&frame.Frame{Type: frame.TypeControl, Payload: []byte(`{"v":1,"type":"hello"}`)}); err != nil {
		t.Fatal(err)
	}
	f, err := host.Recv()
	if err != nil || f.Type != frame.TypeControl || string(f.Payload) != `{"v":1,"type":"hello"}` {
		t.Fatalf("control: %v %+v", err, f)
	}
	payload := bytes.Repeat([]byte{0x1b, '[', 'm', 'x'}, frame.MaxPayload/4)
	const n = 128 // 2 MiB
	go func() {
		for i := 0; i < n; i++ {
			if err := host.Send(&frame.Frame{Type: frame.TypeOutput, StreamID: 1, Seq: uint32(i), Payload: payload}); err != nil {
				t.Errorf("send %d: %v", i, err)
				return
			}
		}
	}()
	for i := 0; i < n; i++ {
		f, err := phone.Recv()
		if err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
		if f.Seq != uint32(i) || !bytes.Equal(f.Payload, payload) {
			t.Fatalf("frame %d out of order or corrupted", i)
		}
	}
	if phone.LocalCertFP() != host.RemoteCertFP() || host.LocalCertFP() != phone.RemoteCertFP() {
		t.Fatalf("DTLS fingerprints do not line up:\n%s %s\n%s %s",
			phone.LocalCertFP(), host.RemoteCertFP(), host.LocalCertFP(), phone.RemoteCertFP())
	}
	if len(phone.LocalCertFP()) != 64 || phone.Transport() != "dtls" {
		t.Fatalf("fingerprint %q transport %q", phone.LocalCertFP(), phone.Transport())
	}
}

func TestDirectLoopback(t *testing.T) {
	phone, host := pair(t, Config{IncludeLoopback: true, UDPOnly: true})
	if phone.Path() != transport.PathDirect {
		t.Fatalf("path %s", phone.Path())
	}
	exchange(t, phone, host)
}

// startTURN runs an in-process TURN server using TURN REST credentials, the
// same scheme coturn uses with use-auth-secret.
func startTURN(t *testing.T, secret string) string {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	const realm = "prw.test"
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:       realm,
		AuthHandler: turn.LongTermTURNRESTAuthHandler(secret, nil),
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            udp,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return udp.LocalAddr().String()
}

func TestForcedTURNRelay(t *testing.T) {
	const secret = "TEST-ONLY-turn-secret"
	addr := startTURN(t, secret)
	user, pass, err := turn.GenerateLongTermTURNRESTCredentials(secret, "att-1", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ForceRelay:      true,
		IncludeLoopback: true,
		UDPOnly:         true,
		ICEServers:      []webrtc.ICEServer{{URLs: []string{"turn:" + addr + "?transport=udp"}, Username: user, Credential: pass}},
	}
	phone, host := pair(t, cfg)
	if phone.Path() != transport.PathTURN || host.Path() != transport.PathTURN {
		t.Fatalf("paths %s/%s", phone.Path(), host.Path())
	}
	exchange(t, phone, host)
}

func TestBadTURNCredentialFails(t *testing.T) {
	addr := startTURN(t, "TEST-ONLY-real")
	user, pass, _ := turn.GenerateLongTermTURNRESTCredentials("TEST-ONLY-wrong", "att-2", 10*time.Minute)
	cfg := Config{Offerer: true, ForceRelay: true, IncludeLoopback: true, UDPOnly: true,
		ICEServers: []webrtc.ICEServer{{URLs: []string{"turn:" + addr}, Username: user, Credential: pass}}}
	var relayCands atomic.Int32
	cfg.OnSignal = func(s Signal) {
		if s.Type == "ice_candidate" && bytes.Contains([]byte(s.Candidate), []byte("typ relay")) {
			relayCands.Add(1)
		}
	}
	p, err := NewPeer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if n := relayCands.Load(); n != 0 {
		t.Fatalf("got %d relay candidates with a wrong TURN secret", n)
	}
}
