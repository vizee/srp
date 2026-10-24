package protocol

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"time"
)

type Hello struct {
	Version     int      `json:"version"`
	Type        string   `json:"type"`
	TimestampMS int64    `json:"timestamp_ms"`
	Services    []string `json:"services,omitempty"`
	ID          string   `json:"id,omitempty"`
}
type HandshakeError struct {
	Sent bool
	Err  error
}

func (e *HandshakeError) Error() string { return fmt.Sprintf("handshake (sent=%t): %v", e.Sent, e.Err) }
func (e *HandshakeError) Unwrap() error { return e.Err }

var namePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func ValidID(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && s == hex.EncodeToString(b)
}

func encodeHello(k *Keys, h Hello) ([]byte, error) {
	payload, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxMessageSize {
		return nil, errors.New("handshake is too large")
	}
	wire := make([]byte, 16+24+4+len(payload)+32)
	if _, err := io.ReadFull(rand.Reader, wire[:40]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(wire[40:44], uint32(len(payload)))
	copy(wire[44:], payload)
	mac := hmac.New(sha256.New, k.mac)
	mac.Write(wire[:len(wire)-32])
	copy(wire[len(wire)-32:], mac.Sum(nil))
	block, err := aes.NewCipher(k.enc)
	if err != nil {
		return nil, err
	}
	cipher.NewCTR(block, wire[:16]).XORKeyStream(wire[16:], wire[16:])
	return wire, nil
}

func readHello(r io.Reader, k *Keys, now time.Time) (Hello, []byte, [24]byte, error) {
	var h Hello
	var nonce [24]byte
	prefix := make([]byte, 44)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return h, nil, nonce, err
	}
	wire := bytes.Clone(prefix)
	block, err := aes.NewCipher(k.enc)
	if err != nil {
		return h, nil, nonce, err
	}
	ctr := cipher.NewCTR(block, prefix[:16])
	ctr.XORKeyStream(prefix[16:], prefix[16:])
	n := binary.BigEndian.Uint32(prefix[40:44])
	if n == 0 || n > MaxMessageSize {
		return h, nil, nonce, errors.New("invalid handshake length")
	}
	tail := make([]byte, int(n)+32)
	if _, err := io.ReadFull(r, tail); err != nil {
		return h, nil, nonce, err
	}
	wire = append(wire, tail...)
	ctr.XORKeyStream(tail, tail)
	mac := hmac.New(sha256.New, k.mac)
	mac.Write(prefix)
	mac.Write(tail[:n])
	if !hmac.Equal(mac.Sum(nil), tail[n:]) {
		return h, nil, nonce, errors.New("invalid handshake authentication")
	}
	dec := json.NewDecoder(bytes.NewReader(tail[:n]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return h, nil, nonce, err
	}
	if dec.Decode(new(any)) != io.EOF {
		return h, nil, nonce, errors.New("trailing handshake JSON")
	}
	if now.IsZero() {
		now = time.Now()
	}
	if err := validateHello(h, now); err != nil {
		return h, nil, nonce, err
	}
	copy(nonce[:], prefix[16:40])
	return h, wire, nonce, nil
}
func validateHello(h Hello, now time.Time) error {
	if h.Version != 2 {
		return errors.New("unsupported protocol version")
	}
	t := now.UnixMilli()
	if h.TimestampMS <= t-10000 || h.TimestampMS >= t+10000 {
		return errors.New("handshake clock difference must be less than 10 seconds")
	}
	switch h.Type {
	case "control":
		if h.ID != "" || len(h.Services) == 0 || len(h.Services) > 256 {
			return errors.New("invalid control handshake")
		}
		seen := make(map[string]bool)
		for _, name := range h.Services {
			if !namePattern.MatchString(name) || seen[name] {
				return errors.New("invalid or repeated service name")
			}
			seen[name] = true
		}
	case "data":
		if !ValidID(h.ID) || len(h.Services) != 0 {
			return errors.New("invalid data handshake")
		}
	default:
		return errors.New("unknown connection type")
	}
	return nil
}

func handshakeScope(ctx context.Context, raw net.Conn) func() {
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	raw.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	return func() { stop(); raw.SetDeadline(time.Time{}) }
}

func ClientHandshake(ctx context.Context, raw net.Conn, k *Keys, h Hello) (s *Stream, err error) {
	done := handshakeScope(ctx, raw)
	defer done()
	sent := false
	defer func() {
		if err != nil {
			err = &HandshakeError{Sent: sent, Err: err}
		}
	}()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	h.Version = 2
	if h.TimestampMS == 0 {
		h.TimestampMS = time.Now().UnixMilli()
	}
	wire, err := encodeHello(k, h)
	if err != nil {
		return nil, err
	}
	n, err := writeFull(raw, wire)
	sent = n == len(wire)
	if err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err = io.ReadFull(raw, nonce[:]); err != nil {
		return nil, err
	}
	toRelay, toExpose, err := k.session(wire, nonce[:])
	if err != nil {
		return nil, err
	}
	s, err = newStream(raw, toRelay, toExpose)
	if err != nil {
		return nil, err
	}
	m, err := ReadMessage(s)
	if err != nil {
		return nil, err
	}
	if m.Type != "challenge" {
		return nil, errors.New("missing server challenge")
	}
	if err = WriteMessage(s, Message{Type: "confirm"}); err != nil {
		return nil, err
	}
	return s, nil
}

func ServerHandshake(ctx context.Context, raw net.Conn, k *Keys, replay *ReplayCache) (s *Stream, h Hello, err error) {
	done := handshakeScope(ctx, raw)
	defer done()
	if ctx.Err() != nil {
		return nil, h, ctx.Err()
	}
	h, wire, nonce, err := readHello(raw, k, time.Time{})
	if err != nil {
		return nil, h, err
	}
	// Recheck wall time after bounded reads; a slow sender cannot freeze the
	// server's timestamp at the start of the connection.
	now := time.Now()
	if err = validateHello(h, now); err != nil {
		return nil, h, err
	}
	if err = replay.accept(nonce, now); err != nil {
		return nil, h, err
	}
	var serverNonce [32]byte
	if _, err = io.ReadFull(rand.Reader, serverNonce[:]); err != nil {
		return nil, h, err
	}
	if _, err = writeFull(raw, serverNonce[:]); err != nil {
		return nil, h, err
	}
	toRelay, toExpose, err := k.session(wire, serverNonce[:])
	if err != nil {
		return nil, h, err
	}
	s, err = newStream(raw, toExpose, toRelay)
	if err != nil {
		return nil, h, err
	}
	if err = WriteMessage(s, Message{Type: "challenge"}); err != nil {
		return nil, h, err
	}
	m, err := ReadMessage(s)
	if err != nil {
		return nil, h, err
	}
	if m.Type != "confirm" {
		return nil, h, errors.New("missing client confirmation")
	}
	return s, h, nil
}
