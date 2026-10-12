// Package frame implements the ConnRelay data-plane frame codec (protocol v1 §12).
//
// Layout (big-endian):
//
//	0  ver       u8   0x01
//	1  type      u8   CONTROL=1 INPUT=2 OUTPUT=3 CLOSE_STREAM=4
//	2  flags     u8   bit0 FIN, other bits must be zero
//	3  reserved  u8   0x00
//	4  stream_id u16  0 for CONTROL, >=1 for terminal streams
//	6  len       u16  0..16384
//	8  seq       u32  per-stream, per-direction counter (diagnostics only)
//	12 payload
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Version       = 0x01
	HeaderSize    = 12
	MaxPayload    = 16384
	MaxFrameSize  = HeaderSize + MaxPayload
	FlagFIN       = 0x01
	knownFlagMask = FlagFIN
)

// Type is the frame type.
type Type uint8

const (
	TypeControl     Type = 0x01
	TypeInput       Type = 0x02
	TypeOutput      Type = 0x03
	TypeCloseStream Type = 0x04
)

func (t Type) String() string {
	switch t {
	case TypeControl:
		return "CONTROL"
	case TypeInput:
		return "INPUT"
	case TypeOutput:
		return "OUTPUT"
	case TypeCloseStream:
		return "CLOSE_STREAM"
	}
	return fmt.Sprintf("Type(%d)", uint8(t))
}

// ErrProtocol is returned (wrapped) for any malformed frame. Receivers must
// close the transport with the protocol_error code when they see it.
var ErrProtocol = errors.New("protocol_error")

// Frame is one decoded frame. Payload aliases the decode buffer unless copied.
type Frame struct {
	Type     Type
	Flags    uint8
	StreamID uint16
	Seq      uint32
	Payload  []byte
}

// FIN reports whether the FIN flag is set.
func (f *Frame) FIN() bool { return f.Flags&FlagFIN != 0 }

func (f *Frame) validate() error {
	switch f.Type {
	case TypeControl:
		if f.StreamID != 0 {
			return fmt.Errorf("%w: control frame on stream %d", ErrProtocol, f.StreamID)
		}
	case TypeInput, TypeOutput, TypeCloseStream:
		if f.StreamID == 0 {
			return fmt.Errorf("%w: %s frame on stream 0", ErrProtocol, f.Type)
		}
	default:
		return fmt.Errorf("%w: unknown type 0x%02x", ErrProtocol, uint8(f.Type))
	}
	if f.Flags&^knownFlagMask != 0 {
		return fmt.Errorf("%w: unknown flags 0x%02x", ErrProtocol, f.Flags)
	}
	if len(f.Payload) > MaxPayload {
		return fmt.Errorf("%w: payload %d > %d", ErrProtocol, len(f.Payload), MaxPayload)
	}
	return nil
}

// AppendEncode appends the encoded frame to dst.
func AppendEncode(dst []byte, f *Frame) ([]byte, error) {
	if err := f.validate(); err != nil {
		return dst, err
	}
	var h [HeaderSize]byte
	h[0] = Version
	h[1] = byte(f.Type)
	h[2] = f.Flags
	binary.BigEndian.PutUint16(h[4:], f.StreamID)
	binary.BigEndian.PutUint16(h[6:], uint16(len(f.Payload)))
	binary.BigEndian.PutUint32(h[8:], f.Seq)
	dst = append(dst, h[:]...)
	return append(dst, f.Payload...), nil
}

// Encode returns the encoded frame.
func Encode(f *Frame) ([]byte, error) {
	return AppendEncode(make([]byte, 0, HeaderSize+len(f.Payload)), f)
}

func parseHeader(h []byte) (Frame, int, error) {
	if h[0] != Version {
		return Frame{}, 0, fmt.Errorf("%w: unknown version 0x%02x", ErrProtocol, h[0])
	}
	if h[3] != 0 {
		return Frame{}, 0, fmt.Errorf("%w: reserved byte 0x%02x", ErrProtocol, h[3])
	}
	n := int(binary.BigEndian.Uint16(h[6:]))
	if n > MaxPayload {
		return Frame{}, 0, fmt.Errorf("%w: payload %d > %d", ErrProtocol, n, MaxPayload)
	}
	f := Frame{
		Type:     Type(h[1]),
		Flags:    h[2],
		StreamID: binary.BigEndian.Uint16(h[4:]),
		Seq:      binary.BigEndian.Uint32(h[8:]),
	}
	return f, n, nil
}

// Decode parses exactly one frame from msg (one DataChannel message). Trailing
// or missing bytes are a protocol error. The payload aliases msg.
func Decode(msg []byte) (*Frame, error) {
	if len(msg) < HeaderSize {
		return nil, fmt.Errorf("%w: short frame (%d bytes)", ErrProtocol, len(msg))
	}
	f, n, err := parseHeader(msg[:HeaderSize])
	if err != nil {
		return nil, err
	}
	if len(msg) != HeaderSize+n {
		return nil, fmt.Errorf("%w: length mismatch (header %d, body %d)", ErrProtocol, n, len(msg)-HeaderSize)
	}
	f.Payload = msg[HeaderSize:]
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Reader decodes concatenated frames from a byte stream (the inner TLS stream
// of the WSS relay transport). It reuses one internal buffer, so a returned
// frame's payload is only valid until the next call to Next.
type Reader struct {
	r   io.Reader
	buf [MaxFrameSize]byte
}

// NewReader returns a stream frame reader.
func NewReader(r io.Reader) *Reader { return &Reader{r: r} }

// Next reads the next frame. It returns io.EOF only on a clean frame boundary.
func (r *Reader) Next() (*Frame, error) {
	if _, err := io.ReadFull(r.r, r.buf[:HeaderSize]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: truncated header", ErrProtocol)
		}
		return nil, err
	}
	f, n, err := parseHeader(r.buf[:HeaderSize])
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r.r, r.buf[HeaderSize:HeaderSize+n]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: truncated payload", ErrProtocol)
		}
		return nil, err
	}
	f.Payload = r.buf[HeaderSize : HeaderSize+n]
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}
