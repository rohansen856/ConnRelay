package peer

import (
	"context"
	"errors"
	"testing"

	"github.com/rohansen856/connrelay/core/connrelaycore/attest"
	"github.com/rohansen856/connrelay/core/connrelaycore/transport"
)

type sides struct {
	phone, host Params
}

func setup(t *testing.T) sides {
	t.Helper()
	ps, _ := attest.NewSoftwareSigner()
	hs, _ := attest.NewSoftwareSigner()
	ppub, _ := attest.ParsePublicKey(ps.PublicKeySPKI())
	hpub, _ := attest.ParsePublicKey(hs.PublicKeySPKI())
	common := Params{Attempt: "att-1", Nonce: "nonce-1", Cap: "terminal", Impl: "test"}
	phone, host := common, common
	phone.Role, phone.Self, phone.Peer, phone.Signer, phone.PeerKey, phone.Ticket = RolePhone, "phone-1", "host-1", ps, hpub, "TICKET"
	host.Role, host.Self, host.Peer, host.Signer, host.PeerKey = RoleHost, "host-1", "phone-1", hs, ppub
	host.CheckTicket = func(tk string) ([]string, error) {
		if tk != "TICKET" {
			return nil, errors.New("bad ticket")
		}
		return []string{"terminal"}, nil
	}
	return sides{phone, host}
}

func run(t *testing.T, s sides, pc, hc transport.Conn) (error, error) {
	t.Helper()
	defer pc.Close()
	defer hc.Close()
	herr := make(chan error, 1)
	go func() {
		_, err := Handshake(context.Background(), hc, s.host)
		if err != nil {
			hc.Close()
		}
		herr <- err
	}()
	_, perr := Handshake(context.Background(), pc, s.phone)
	if perr != nil {
		pc.Close()
	}
	return perr, <-herr
}

func honest() (transport.Conn, transport.Conn) {
	return transport.Pipe("fpP", "fpH", "fpH", "fpP")
}

func TestHandshakeSucceeds(t *testing.T) {
	pc, hc := honest()
	perr, herr := run(t, setup(t), pc, hc)
	if perr != nil || herr != nil {
		t.Fatalf("phone %v host %v", perr, herr)
	}
}

func TestHandshakeRejects(t *testing.T) {
	cases := map[string]func(s *sides) (transport.Conn, transport.Conn){
		"wrong pinned host key": func(s *sides) (transport.Conn, transport.Conn) {
			other, _ := attest.NewSoftwareSigner()
			s.phone.PeerKey, _ = attest.ParsePublicKey(other.PublicKeySPKI())
			return honest()
		},
		"wrong pinned phone key": func(s *sides) (transport.Conn, transport.Conn) {
			other, _ := attest.NewSoftwareSigner()
			s.host.PeerKey, _ = attest.ParsePublicKey(other.PublicKeySPKI())
			return honest()
		},
		"interposed certificate": func(s *sides) (transport.Conn, transport.Conn) {
			// The phone observes a certificate the host never presented.
			return transport.Pipe("fpP", "fpH", "fpMITM", "fpP")
		},
		"bad ticket": func(s *sides) (transport.Conn, transport.Conn) {
			s.phone.Ticket = "FORGED"
			return honest()
		},
		"nonce mismatch": func(s *sides) (transport.Conn, transport.Conn) {
			s.host.Nonce = "nonce-2"
			return honest()
		},
		"unexpected peer id": func(s *sides) (transport.Conn, transport.Conn) {
			s.phone.Peer = "host-2"
			return honest()
		},
	}
	for name, mk := range cases {
		s := setup(t)
		pc, hc := mk(&s)
		perr, herr := run(t, s, pc, hc)
		if perr == nil || herr == nil {
			t.Errorf("%s: phone %v host %v (both sides must fail)", name, perr, herr)
		}
	}
}
