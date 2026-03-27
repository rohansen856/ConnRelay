// Package webrtc implements the WebRTC DataChannel transport (protocol v1
// §9.1) on Pion: two negotiated, reliable, ordered DataChannels ("prw-ctl" id
// 0 and "prw-term" id 1), DTLS-encrypted, over ICE (direct or TURN).
package webrtc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/core/prwcore/frame"
	"github.com/rohansen856/connrelay/core/prwcore/transport"
)

// Channel labels and IDs.
const (
	CtlLabel  = "prw-ctl"
	TermLabel = "prw-term"
	CtlID     = 0
	TermID    = 1
	// MaxBuffered is the backstop on DataChannel buffered bytes.
	MaxBuffered = 1 << 20
)

// Signal is one signaling message produced or consumed by a Peer.
type Signal struct {
	Type          string `json:"type"` // offer, answer, ice_candidate, ice_complete
	SDP           string `json:"sdp,omitempty"`
	Candidate     string `json:"candidate,omitempty"`
	SDPMid        string `json:"sdp_mid,omitempty"`
	SDPMLineIndex uint16 `json:"sdp_mline_index,omitempty"`
}

// Config configures a Peer.
type Config struct {
	Offerer    bool // the phone offers, the host answers
	ICEServers []webrtc.ICEServer
	ForceRelay bool
	// OnSignal delivers outbound signaling. It must not block for long.
	OnSignal func(Signal)
	// IncludeLoopback adds 127.0.0.1 candidates (tests only).
	IncludeLoopback bool
	// UDPOnly disables ICE-TCP candidate gathering.
	UDPOnly bool
}

// Peer is one side of a WebRTC connection attempt.
type Peer struct {
	cfg  Config
	pc   *webrtc.PeerConnection
	cert webrtc.Certificate
	ctl  *webrtc.DataChannel
	term *webrtc.DataChannel

	mu        sync.Mutex
	remoteSet bool
	pendingIC []webrtc.ICECandidateInit
	opened    int
	ready     chan struct{}
	failed    chan error
	failOnce  sync.Once
}

// NewPeer creates the PeerConnection and both negotiated DataChannels.
func NewPeer(cfg Config) (*Peer, error) {
	var se webrtc.SettingEngine
	se.DetachDataChannels()
	se.SetICETimeouts(5*time.Second, 15*time.Second, 2*time.Second)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetIncludeLoopbackCandidate(cfg.IncludeLoopback)
	nt := []webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6}
	if !cfg.UDPOnly {
		nt = append(nt, webrtc.NetworkTypeTCP4, webrtc.NetworkTypeTCP6)
	}
	se.SetNetworkTypes(nt)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))

	certs, err := generateCert()
	if err != nil {
		return nil, err
	}
	policy := webrtc.ICETransportPolicyAll
	if cfg.ForceRelay {
		policy = webrtc.ICETransportPolicyRelay
	}
	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers:         cfg.ICEServers,
		ICETransportPolicy: policy,
		Certificates:       []webrtc.Certificate{certs},
	})
	if err != nil {
		return nil, err
	}
	p := &Peer{cfg: cfg, pc: pc, cert: certs, ready: make(chan struct{}), failed: make(chan error, 1)}

	neg := true
	mk := func(label string, id uint16) (*webrtc.DataChannel, error) {
		ordered := true
		return pc.CreateDataChannel(label, &webrtc.DataChannelInit{Negotiated: &neg, ID: &id, Ordered: &ordered})
	}
	if p.ctl, err = mk(CtlLabel, CtlID); err != nil {
		pc.Close()
		return nil, err
	}
	if p.term, err = mk(TermLabel, TermID); err != nil {
		pc.Close()
		return nil, err
	}
	for _, dc := range []*webrtc.DataChannel{p.ctl, p.term} {
		dc.SetBufferedAmountLowThreshold(MaxBuffered / 2)
		dc.OnOpen(p.channelOpened)
	}
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			p.signal(Signal{Type: "ice_complete"})
			return
		}
		ci := c.ToJSON()
		s := Signal{Type: "ice_candidate", Candidate: ci.Candidate}
		if ci.SDPMid != nil {
			s.SDPMid = *ci.SDPMid
		}
		if ci.SDPMLineIndex != nil {
			s.SDPMLineIndex = *ci.SDPMLineIndex
		}
		p.signal(s)
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateClosed {
			p.fail(fmt.Errorf("webrtc: connection %s", st))
		}
	})
	return p, nil
}

func generateCert() (webrtc.Certificate, error) {
	k, err := attest.NewSoftwareSigner()
	if err != nil {
		return webrtc.Certificate{}, err
	}
	c, err := webrtc.GenerateCertificate(k.Key)
	if err != nil {
		return webrtc.Certificate{}, err
	}
	return *c, nil
}

func (p *Peer) signal(s Signal) {
	if p.cfg.OnSignal != nil {
		p.cfg.OnSignal(s)
	}
}

func (p *Peer) fail(err error) {
	p.failOnce.Do(func() { p.failed <- err })
}

func (p *Peer) channelOpened() {
	p.mu.Lock()
	p.opened++
	done := p.opened == 2
	p.mu.Unlock()
	if done {
		close(p.ready)
	}
}

// Start creates and signals the offer (offerer only).
func (p *Peer) Start() error {
	if !p.cfg.Offerer {
		return nil
	}
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := p.pc.SetLocalDescription(offer); err != nil {
		return err
	}
	p.signal(Signal{Type: "offer", SDP: offer.SDP})
	return nil
}

// HandleSignal applies one inbound signaling message.
func (p *Peer) HandleSignal(s Signal) error {
	switch s.Type {
	case "offer":
		if p.cfg.Offerer {
			return errors.New("webrtc: unexpected offer")
		}
		if err := p.setRemote(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: s.SDP}); err != nil {
			return err
		}
		ans, err := p.pc.CreateAnswer(nil)
		if err != nil {
			return err
		}
		if err := p.pc.SetLocalDescription(ans); err != nil {
			return err
		}
		p.signal(Signal{Type: "answer", SDP: ans.SDP})
	case "answer":
		if !p.cfg.Offerer {
			return errors.New("webrtc: unexpected answer")
		}
		return p.setRemote(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: s.SDP})
	case "ice_candidate":
		mid, idx := s.SDPMid, s.SDPMLineIndex
		ci := webrtc.ICECandidateInit{Candidate: s.Candidate, SDPMid: &mid, SDPMLineIndex: &idx}
		p.mu.Lock()
		if !p.remoteSet {
			p.pendingIC = append(p.pendingIC, ci)
			p.mu.Unlock()
			return nil
		}
		p.mu.Unlock()
		return p.pc.AddICECandidate(ci)
	case "ice_complete":
	default:
		return fmt.Errorf("webrtc: unknown signal %q", s.Type)
	}
	return nil
}

func (p *Peer) setRemote(sd webrtc.SessionDescription) error {
	if err := p.pc.SetRemoteDescription(sd); err != nil {
		return err
	}
	p.mu.Lock()
	p.remoteSet = true
	pending := p.pendingIC
	p.pendingIC = nil
	p.mu.Unlock()
	for _, c := range pending {
		if err := p.pc.AddICECandidate(c); err != nil {
			return err
		}
	}
	return nil
}

// Wait blocks until both DataChannels are open and returns the Conn.
func (p *Peer) Wait(ctx context.Context) (transport.Conn, error) {
	select {
	case <-p.ready:
	case err := <-p.failed:
		p.pc.Close()
		return nil, err
	case <-ctx.Done():
		p.pc.Close()
		return nil, ctx.Err()
	}
	return p.newConn()
}

// Close tears down the peer connection.
func (p *Peer) Close() error { return p.pc.Close() }

func (p *Peer) newConn() (*conn, error) {
	ctlRW, err := p.ctl.Detach()
	if err != nil {
		return nil, err
	}
	termRW, err := p.term.Detach()
	if err != nil {
		return nil, err
	}
	dtls := p.pc.SCTP().Transport()
	remoteDER := dtls.GetRemoteCertificate()
	if len(remoteDER) == 0 {
		return nil, errors.New("webrtc: no remote certificate")
	}
	localFP, err := certFingerprint(p.cert)
	if err != nil {
		return nil, err
	}
	path := transport.PathDirect
	if pair, err := dtls.ICETransport().GetSelectedCandidatePair(); err == nil && pair != nil &&
		(pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay) {
		path = transport.PathTURN
	}
	c := &conn{
		p: p, ctlRW: ctlRW, termRW: termRW, path: path,
		localFP: localFP, remoteFP: attest.Fingerprint(remoteDER),
		in: make(chan *frame.Frame, 64), errc: make(chan error, 2), done: make(chan struct{}),
		low: map[*webrtc.DataChannel]chan struct{}{p.ctl: make(chan struct{}, 1), p.term: make(chan struct{}, 1)},
	}
	for dc, ch := range c.low {
		ch := ch
		dc.OnBufferedAmountLow(func() {
			select {
			case ch <- struct{}{}:
			default:
			}
		})
	}
	go c.readLoop(ctlRW)
	go c.readLoop(termRW)
	return c, nil
}

func certFingerprint(c webrtc.Certificate) (string, error) {
	fps, err := c.GetFingerprints()
	if err != nil {
		return "", err
	}
	for _, f := range fps {
		if f.Algorithm == "sha-256" {
			return strings.ToLower(strings.ReplaceAll(f.Value, ":", "")), nil
		}
	}
	return "", errors.New("webrtc: no sha-256 fingerprint")
}

type conn struct {
	p             *Peer
	ctlRW, termRW io.ReadWriteCloser
	path          string
	localFP       string
	remoteFP      string
	wmu           sync.Mutex
	in            chan *frame.Frame
	errc          chan error
	done          chan struct{}
	closeOnce     sync.Once
	low           map[*webrtc.DataChannel]chan struct{}
}

func (c *conn) readLoop(rw io.Reader) {
	buf := make([]byte, frame.MaxFrameSize)
	for {
		n, err := rw.Read(buf)
		if err != nil {
			c.errc <- err
			return
		}
		f, err := frame.Decode(buf[:n])
		if err != nil {
			c.errc <- err
			return
		}
		f.Payload = append([]byte(nil), f.Payload...)
		select {
		case c.in <- f:
		case <-c.done:
			return
		}
	}
}

func (c *conn) Send(f *frame.Frame) error {
	b, err := frame.Encode(f)
	if err != nil {
		return err
	}
	dc, rw := c.p.term, c.termRW
	if f.Type == frame.TypeControl {
		dc, rw = c.p.ctl, c.ctlRW
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	for dc.BufferedAmount() > MaxBuffered {
		select {
		case <-c.low[dc]:
		case <-c.done:
			return transport.ErrClosed
		case <-time.After(100 * time.Millisecond):
		}
	}
	_, err = rw.Write(b)
	return err
}

func (c *conn) Recv() (*frame.Frame, error) {
	select {
	case f := <-c.in:
		return f, nil
	case err := <-c.errc:
		return nil, err
	case <-c.done:
		return nil, transport.ErrClosed
	}
}

func (c *conn) Transport() string    { return attest.TransportDTLS }
func (c *conn) Path() string         { return c.path }
func (c *conn) LocalCertFP() string  { return c.localFP }
func (c *conn) RemoteCertFP() string { return c.remoteFP }

func (c *conn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return c.p.pc.Close()
}
