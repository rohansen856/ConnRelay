package frame

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite protocol/vectors/frames.json")

// vector is one entry of protocol/vectors/frames.json, shared with other
// implementations of the frame codec.
type vector struct {
	Name     string `json:"name"`
	Hex      string `json:"hex"`
	Valid    bool   `json:"valid"`
	Type     uint8  `json:"type,omitempty"`
	Flags    uint8  `json:"flags,omitempty"`
	StreamID uint16 `json:"stream_id,omitempty"`
	Seq      uint32 `json:"seq,omitempty"`
	Payload  string `json:"payload_hex,omitempty"`
}

const vectorsPath = "../../../protocol/vectors/frames.json"

func buildVectors(t *testing.T) []vector {
	t.Helper()
	var out []vector
	add := func(name string, f Frame) {
		b, err := Encode(&f)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, vector{Name: name, Hex: hex.EncodeToString(b), Valid: true, Type: uint8(f.Type),
			Flags: f.Flags, StreamID: f.StreamID, Seq: f.Seq, Payload: hex.EncodeToString(f.Payload)})
	}
	add("control hello", Frame{Type: TypeControl, Payload: []byte(`{"v":1,"type":"hello","payload":{"pv_min":1,"pv_max":1}}`)})
	add("input ctrl-c", Frame{Type: TypeInput, StreamID: 1, Seq: 0, Payload: []byte{0x03}})
	add("output empty", Frame{Type: TypeOutput, StreamID: 1, Seq: 7})
	add("output utf8", Frame{Type: TypeOutput, StreamID: 2, Seq: 0xfffffffe, Payload: []byte("✨ ok\r\n")})
	add("output max payload", Frame{Type: TypeOutput, StreamID: 65535, Seq: 1, Payload: bytes.Repeat([]byte{0xab}, MaxPayload)})
	add("close stream fin", Frame{Type: TypeCloseStream, StreamID: 3, Flags: FlagFIN})

	bad := func(name, h string) { out = append(out, vector{Name: name, Hex: h}) }
	bad("bad version", "02030000000100010000000041")
	bad("unknown type", "01090000000100010000000041")
	bad("unknown flag", "01038000000100010000000041")
	bad("reserved byte set", "01030001000100010000000041")
	bad("length over max", "0103000000014001000000000041")
	bad("length mismatch", "010300000001000500000000414243")
	bad("control on stream 1", "010100000001000100000000"+"7b")
	bad("terminal on stream 0", "010300000000000100000000"+"41")
	bad("short header", "0103000000")
	return out
}

func TestGoldenVectors(t *testing.T) {
	want := buildVectors(t)
	if *update {
		b, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(filepath.Clean(vectorsPath), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Clean(vectorsPath))
	if err != nil {
		t.Fatalf("read vectors (run with -update to create): %v", err)
	}
	var got []vector
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("vector file has %d entries, code produces %d; run with -update", len(got), len(want))
	}
	for _, v := range got {
		b, _ := hex.DecodeString(v.Hex)
		f, err := Decode(b)
		if !v.Valid {
			if !errors.Is(err, ErrProtocol) {
				t.Errorf("%s: want protocol error, got %v", v.Name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if uint8(f.Type) != v.Type || f.Flags != v.Flags || f.StreamID != v.StreamID || f.Seq != v.Seq || hex.EncodeToString(f.Payload) != v.Payload {
			t.Errorf("%s: decoded %+v", v.Name, f)
		}
	}
}
