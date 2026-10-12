package innertls

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func handshake(t *testing.T, serverPin, clientPin func(srv, cli *Identity) string) (error, error) {
	t.Helper()
	srv, _ := NewIdentity("a1")
	cli, _ := NewIdentity("a1")
	a, b := tcpPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errs := make(chan error, 1)
	go func() {
		tc, err := Server(ctx, a, srv, serverPin(srv, cli))
		if err == nil {
			buf := make([]byte, 4)
			_, err = io.ReadFull(tc, buf)
			if err == nil {
				_, err = tc.Write(buf)
			}
		} else {
			a.Close()
		}
		errs <- err
	}()
	tc, cerr := Client(ctx, b, cli, clientPin(srv, cli))
	if cerr == nil {
		_, _ = tc.Write([]byte("ping"))
		buf := make([]byte, 4)
		_, cerr = io.ReadFull(tc, buf)
		if cerr == nil && string(buf) != "ping" {
			cerr = errors.New("echo mismatch")
		}
	} else {
		b.Close()
	}
	return <-errs, cerr
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acc <- c }()
	b, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return <-acc, b
}

func TestPinnedHandshake(t *testing.T) {
	serr, cerr := handshake(t,
		func(_, cli *Identity) string { return cli.Fingerprint },
		func(srv, _ *Identity) string { return srv.Fingerprint })
	if serr != nil || cerr != nil {
		t.Fatalf("server %v client %v", serr, cerr)
	}
}

func TestClientRejectsSubstitutedServer(t *testing.T) {
	_, cerr := handshake(t,
		func(_, cli *Identity) string { return cli.Fingerprint },
		func(_, _ *Identity) string { return "0000" })
	if cerr == nil {
		t.Fatal("client accepted wrong server certificate")
	}
}

func TestServerRejectsSubstitutedClient(t *testing.T) {
	serr, _ := handshake(t,
		func(_, _ *Identity) string { return "0000" },
		func(srv, _ *Identity) string { return srv.Fingerprint })
	if serr == nil {
		t.Fatal("server accepted wrong client certificate")
	}
}
