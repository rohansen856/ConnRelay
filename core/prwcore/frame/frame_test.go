package frame

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	cases := []Frame{
		{Type: TypeControl, Payload: []byte(`{"v":1,"type":"hello"}`)},
		{Type: TypeInput, StreamID: 1, Seq: 7, Payload: []byte("ls\r")},
		{Type: TypeOutput, StreamID: 65535, Seq: 1<<32 - 1, Payload: bytes.Repeat([]byte{0xff}, MaxPayload)},
		{Type: TypeOutput, StreamID: 2, Payload: nil},
		{Type: TypeCloseStream, StreamID: 3, Flags: FlagFIN},
	}
	for _, c := range cases {
		b, err := Encode(&c)
		if err != nil {
			t.Fatalf("encode %v: %v", c.Type, err)
		}
		if len(b) != HeaderSize+len(c.Payload) {
			t.Fatalf("size %d", len(b))
		}
		got, err := Decode(b)
		if err != nil {
			t.Fatalf("decode %v: %v", c.Type, err)
		}
		if got.Type != c.Type || got.Flags != c.Flags || got.StreamID != c.StreamID || got.Seq != c.Seq || !bytes.Equal(got.Payload, c.Payload) {
			t.Fatalf("mismatch: %+v vs %+v", got, c)
		}
	}
}

func TestHeaderLayout(t *testing.T) {
	b, err := Encode(&Frame{Type: TypeOutput, Flags: FlagFIN, StreamID: 0x0102, Seq: 0x0a0b0c0d, Payload: []byte{0xAA}})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x01, 0x03, 0x01, 0x00, 0x01, 0x02, 0x00, 0x01, 0x0a, 0x0b, 0x0c, 0x0d, 0xAA}
	if !bytes.Equal(b, want) {
		t.Fatalf("got % x\nwant % x", b, want)
	}
}

func TestEncodeRejects(t *testing.T) {
	bad := []Frame{
		{Type: 0x05, StreamID: 1},
		{Type: TypeControl, StreamID: 1},
		{Type: TypeInput, StreamID: 0},
		{Type: TypeOutput, StreamID: 1, Flags: 0x02},
		{Type: TypeOutput, StreamID: 1, Payload: make([]byte, MaxPayload+1)},
	}
	for i, f := range bad {
		if _, err := Encode(&f); !errors.Is(err, ErrProtocol) {
			t.Fatalf("case %d: want ErrProtocol, got %v", i, err)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	good, _ := Encode(&Frame{Type: TypeOutput, StreamID: 1, Payload: []byte("hi")})
	mut := func(f func(b []byte) []byte) []byte {
		c := append([]byte(nil), good...)
		return f(c)
	}
	bad := map[string][]byte{
		"short":         good[:5],
		"bad version":   mut(func(b []byte) []byte { b[0] = 2; return b }),
		"reserved":      mut(func(b []byte) []byte { b[3] = 1; return b }),
		"unknown flag":  mut(func(b []byte) []byte { b[2] = 0x80; return b }),
		"unknown type":  mut(func(b []byte) []byte { b[1] = 9; return b }),
		"len too large": mut(func(b []byte) []byte { b[6], b[7] = 0x40, 0x01; return b }),
		"trailing":      append(append([]byte(nil), good...), 0),
		"truncated":     good[:len(good)-1],
		"ctl on stream": mut(func(b []byte) []byte { b[1] = byte(TypeControl); return b }),
	}
	for name, b := range bad {
		if _, err := Decode(b); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: want ErrProtocol, got %v", name, err)
		}
	}
}

func TestStreamReader(t *testing.T) {
	var buf bytes.Buffer
	frames := []Frame{
		{Type: TypeControl, Payload: []byte(`{}`)},
		{Type: TypeOutput, StreamID: 1, Seq: 1, Payload: bytes.Repeat([]byte("x"), MaxPayload)},
		{Type: TypeInput, StreamID: 1, Seq: 2, Payload: []byte("y")},
	}
	for i := range frames {
		b, _ := Encode(&frames[i])
		buf.Write(b)
	}
	r := NewReader(&buf)
	for i := range frames {
		f, err := r.Next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if f.Type != frames[i].Type || !bytes.Equal(f.Payload, frames[i].Payload) {
			t.Fatalf("frame %d mismatch", i)
		}
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestStreamReaderTruncated(t *testing.T) {
	b, _ := Encode(&Frame{Type: TypeOutput, StreamID: 1, Payload: []byte("hello")})
	for _, n := range []int{3, HeaderSize + 2} {
		_, err := NewReader(bytes.NewReader(b[:n])).Next()
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("cut %d: want ErrProtocol, got %v", n, err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	seed, _ := Encode(&Frame{Type: TypeOutput, StreamID: 1, Payload: []byte("seed")})
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := Decode(b)
		if err != nil {
			return
		}
		re, err := Encode(fr)
		if err != nil {
			t.Fatalf("decoded frame failed to re-encode: %v", err)
		}
		if !bytes.Equal(re, b) {
			t.Fatalf("round trip mismatch")
		}
	})
}
