package protocol

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func testKeys(t *testing.T) *Keys {
	t.Helper()
	k, e := NewKeys(bytes.Repeat([]byte{7}, 32))
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func testHello() Hello {
	return Hello{Version: 2, Type: "control", TimestampMS: time.Now().UnixMilli(), Services: []string{"ssh", "egress.baidu"}}
}

func TestHelloLayoutAndAuthentication(t *testing.T) {
	k := testKeys(t)
	h := testHello()
	wire, err := encodeHello(k, h)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Clone(wire[16:])
	block, _ := aes.NewCipher(k.enc)
	cipher.NewCTR(block, wire[:16]).XORKeyStream(plain, plain)
	n := int(binary.BigEndian.Uint32(plain[24:28]))
	if len(wire) != 16+24+4+n+32 {
		t.Fatalf("unexpected frame length %d", len(wire))
	}
	got, transcript, nonce, err := readHello(bytes.NewReader(wire), k, time.Now())
	if err != nil || got.Services[1] != "egress.baidu" || !bytes.Equal(wire, transcript) || !bytes.Equal(nonce[:], plain[:24]) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, at := range []int{0, 16, 40, 44, len(wire) - 1} {
		changed := bytes.Clone(wire)
		changed[at] ^= 1
		if _, _, _, err := readHello(bytes.NewReader(changed), k, time.Now()); err == nil {
			t.Errorf("accepted mutation at %d", at)
		}
	}
	for _, cut := range []int{0, 15, 16, 43, len(wire) - 1} {
		if _, _, _, err := readHello(bytes.NewReader(wire[:cut]), k, time.Now()); err == nil {
			t.Errorf("accepted truncation %d", cut)
		}
	}
	other, _ := NewKeys(bytes.Repeat([]byte{8}, 32))
	if _, _, _, err := readHello(bytes.NewReader(wire), other, time.Now()); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestTimestampBoundaries(t *testing.T) {
	now := time.Unix(1000000, 0)
	for _, offset := range []int64{-10001, -10000, -9999, 0, 9999, 10000, 10001} {
		h := testHello()
		h.TimestampMS = now.UnixMilli() + offset
		wire, e := encodeHello(testKeys(t), h)
		if e != nil {
			t.Fatal(e)
		}
		_, _, _, err := readHello(bytes.NewReader(wire), testKeys(t), now)
		valid := offset > -10000 && offset < 10000
		if (err == nil) != valid {
			t.Errorf("offset %d: %v", offset, err)
		}
	}
}

func TestReplayCacheGlobalAndConcurrent(t *testing.T) {
	c := NewReplayCache(2)
	now := time.Now()
	var nonce [24]byte
	var wg sync.WaitGroup
	results := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- c.accept(nonce, now) }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("accepted %d duplicates", successes)
	}
	if c.accept(nonce, now.Add(11*time.Second)) == nil {
		t.Fatal("nonce expired too soon for future-dated hello")
	}
	if c.accept(nonce, now.Add(20*time.Second)) != nil {
		t.Fatal("nonce did not expire")
	}
	nonce[0] = 1
	if c.accept(nonce, now.Add(20*time.Second)) != nil {
		t.Fatal("second nonce rejected")
	}
	nonce[0] = 2
	if c.accept(nonce, now.Add(20*time.Second)) == nil {
		t.Fatal("unexpired entries evicted at capacity")
	}
}

func TestHandshakeRoundTripAndSentBoundary(t *testing.T) {
	k := testKeys(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		s, h, e := ServerHandshake(ctx, b, k, NewReplayCache(10))
		if e == nil && h.Type != "control" {
			e = errors.New("wrong type")
		}
		if e == nil {
			e = WriteMessage(s, Message{Type: "ready", Accepted: h.Services})
		}
		done <- e
	}()
	s, e := ClientHandshake(ctx, a, k, testHello())
	if e != nil {
		t.Fatal(e)
	}
	m, e := ReadMessage(s)
	if e != nil || m.Type != "ready" {
		t.Fatalf("%+v %v", m, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	a2, b2 := net.Pipe()
	defer a2.Close()
	go func() { io.CopyN(io.Discard, b2, 1<<20); b2.Close() }()
	b2.Close()
	_, e = ClientHandshake(ctx, a2, k, testHello())
	var he *HandshakeError
	if !errors.As(e, &he) || he.Sent {
		t.Fatalf("pre-send failure: %v", e)
	}
	a3, b3 := net.Pipe()
	defer a3.Close()
	go func() { defer b3.Close(); readHello(b3, k, time.Now()) }()
	_, e = ClientHandshake(ctx, a3, k, testHello())
	if !errors.As(e, &he) || !he.Sent {
		t.Fatalf("post-send failure: %v", e)
	}
}

type shortWriter struct {
	bytes.Buffer
	limit int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.Buffer.Write(p)
}

func TestStreamRecordsAndHalfClose(t *testing.T) {
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	for _, size := range []int{0, 1, 32768, 32769, 1 << 20} {
		w := &memoryConn{}
		out, _ := newStream(w, k1, k2)
		payload := bytes.Repeat([]byte{0x41}, size)
		if n, e := out.Write(payload); n != size || e != nil {
			t.Fatalf("write %d: %d %v", size, n, e)
		}
		if e := out.CloseWrite(); e != nil {
			t.Fatal(e)
		}
		original := bytes.Clone(w.Bytes())
		in, _ := newStream(w, k2, k1)
		got, e := io.ReadAll(in)
		if e != nil || !bytes.Equal(got, payload) {
			t.Fatalf("read %d: %d %v", size, len(got), e)
		}
		for _, bad := range [][]byte{original[:len(original)-1], nil, append(bytes.Clone(original[:4]), bytes.Repeat([]byte{0}, len(original)-4)...)} {
			in, _ := newStream(&memoryConn{Buffer: *bytes.NewBuffer(bad)}, k2, k1)
			if _, e := io.ReadAll(in); e == nil {
				t.Fatal("accepted corrupt/truncated stream")
			}
		}
	}
	w := &memoryConn{}
	out, _ := newStream(w, k1, k2)
	out.writeSeq = 1 << 32
	if _, e := out.Write([]byte("x")); e == nil {
		t.Fatal("nonce limit not enforced")
	}
}

type memoryConn struct{ bytes.Buffer }

func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return nil }
func (*memoryConn) RemoteAddr() net.Addr             { return nil }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

func TestMessageShortWriteAndBounds(t *testing.T) {
	w := &shortWriter{limit: 3}
	if e := WriteMessage(w, Message{Type: "heartbeat"}); e != nil {
		t.Fatal(e)
	}
	m, e := ReadMessage(bytes.NewReader(w.Bytes()))
	if e != nil || m.Type != "heartbeat" {
		t.Fatalf("%+v %v", m, e)
	}
	for _, b := range [][]byte{{0, 0, 0, 0}, {0, 1, 0, 1}, {0, 0, 0, 4, '{', '}'}} {
		if _, e := ReadMessage(bytes.NewReader(b)); e == nil {
			t.Fatal("accepted malformed message")
		}
	}
	if e := WriteMessage(&shortWriter{limit: 0}, Message{Type: "heartbeat"}); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal(e)
	}
}

func FuzzReadHello(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 44))
	k, _ := NewKeys(make([]byte, 32))
	f.Fuzz(func(t *testing.T, b []byte) { readHello(bytes.NewReader(b), k, time.Now()) })
}
func FuzzReadMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Fuzz(func(t *testing.T, b []byte) { ReadMessage(bytes.NewReader(b)) })
}

func TestHandshakeChecksTimeAfterReadingHello(t *testing.T) {
	k := testKeys(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		s, _, e := ServerHandshake(ctx, b, k, NewReplayCache(10))
		if e == nil {
			e = WriteMessage(s, Message{Type: "ready"})
		}
		done <- e
	}()
	time.Sleep(700 * time.Millisecond)
	h := testHello()
	h.TimestampMS = time.Now().Add(9500 * time.Millisecond).UnixMilli()
	s, e := ClientHandshake(ctx, a, k, h)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ReadMessage(s); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestStreamRejectsReplayReflectionAndReorder(t *testing.T) {
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	w := &memoryConn{}
	s, _ := newStream(w, k1, k2)
	s.Write([]byte("first"))
	s.Write([]byte("second"))
	s.CloseWrite()
	raw := bytes.Clone(w.Bytes())
	end := 4 + int(binary.BigEndian.Uint32(raw[:4]))
	end2 := end + 4 + int(binary.BigEndian.Uint32(raw[end:end+4]))
	for _, wire := range [][]byte{append(bytes.Clone(raw[:end]), raw...), append(append(bytes.Clone(raw[end:end2]), raw[:end]...), raw[end2:]...)} {
		s, _ := newStream(&memoryConn{Buffer: *bytes.NewBuffer(wire)}, k2, k1)
		if _, e := io.ReadAll(s); e == nil {
			t.Fatal("replay/order accepted")
		}
	}
	for _, readKey := range [][]byte{k2, bytes.Repeat([]byte{3}, 32)} {
		s, _ := newStream(&memoryConn{Buffer: *bytes.NewBuffer(raw)}, k1, readKey)
		if _, e := io.ReadAll(s); e == nil {
			t.Fatal("reflection/session substitution accepted")
		}
	}
}

func TestRecordedConfirmCannotAuthenticateAfterRelayRestart(t *testing.T) {
	k := testKeys(t)
	wire, e := encodeHello(k, testHello())
	if e != nil {
		t.Fatal(e)
	}
	var oldConfirmation []byte
	for attempt := 0; attempt < 2; attempt++ {
		a, b := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		done := make(chan error, 1)
		go func() { defer b.Close(); _, _, e := ServerHandshake(ctx, b, k, NewReplayCache(10)); done <- e }()
		writeFull(a, wire)
		nonce := make([]byte, 32)
		if _, e := io.ReadFull(a, nonce); e != nil {
			t.Fatal(e)
		}
		toRelay, toExpose, _ := k.session(wire, nonce)
		s, _ := newStream(a, toRelay, toExpose)
		if _, e := ReadMessage(s); e != nil {
			t.Fatal(e)
		}
		if attempt == 0 {
			capture := &memoryConn{}
			writer, _ := newStream(capture, toRelay, toExpose)
			WriteMessage(writer, Message{Type: "confirm"})
			oldConfirmation = bytes.Clone(capture.Bytes())
		}
		writeFull(a, oldConfirmation)
		e := <-done
		a.Close()
		cancel()
		if (e == nil) != (attempt == 0) {
			t.Fatalf("attempt %d: %v", attempt, e)
		}
	}
}
