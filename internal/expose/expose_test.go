package expose

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vizee/srp/internal/protocol"
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}
func key(t *testing.T) *protocol.Keys {
	t.Helper()
	k, e := protocol.NewKeys(bytes.Repeat([]byte{9}, 32))
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func cfg(t *testing.T, remote, target string) Config {
	return Config{Keys: key(t), Remote: remote, Targets: map[string]string{"ssh": target}, Logger: log.New(io.Discard, "", 0)}
}
func wait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("task did not stop")
	}
}

func TestExposeOnlyAdvertisesNames(t *testing.T) {
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hello := make(chan protocol.Hello, 1)
	go func() {
		raw, e := ln.Accept()
		if e != nil {
			return
		}
		defer raw.Close()
		s, h, e := protocol.ServerHandshake(ctx, raw, key(t), protocol.NewReplayCache(20))
		if e != nil {
			return
		}
		hello <- h
		protocol.WriteMessage(s, protocol.Message{Type: "ready", Accepted: []string{"ssh"}})
		<-ctx.Done()
	}()
	done := make(chan struct{})
	go func() { defer close(done); Run(ctx, cfg(t, ln.Addr().String(), "192.168.42.5:2222")) }()
	select {
	case h := <-hello:
		if h.Type != "control" || len(h.Services) != 1 || h.Services[0] != "ssh" || h.ID != "" {
			t.Fatalf("%+v", h)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no registration")
	}
	cancel()
	wait(t, done)
}

func TestDialFailureRetriesBeforeHelloSent(t *testing.T) {
	remote, backend := listen(t), listen(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := newSession(ctx, cfg(t, remote.Addr().String(), backend.Addr().String()))
	defer s.close()
	var attempts atomic.Int32
	realDial := s.dial
	s.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		if addr == remote.Addr().String() && attempts.Add(1) < 3 {
			return nil, errors.New("transient connect failure")
		}
		return realDial(ctx, addr)
	}
	go func() {
		raw, e := remote.Accept()
		if e != nil {
			return
		}
		defer raw.Close()
		stream, _, e := protocol.ServerHandshake(ctx, raw, key(t), protocol.NewReplayCache(20))
		if e == nil {
			protocol.WriteMessage(stream, protocol.Message{Type: "error", Code: "invalid_data_id"})
		}
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.openData(protocol.Message{Type: "open", Service: "ssh", ID: string(bytes.Repeat([]byte{'a'}, 64))}, func() {})
	}()
	wait(t, done)
	if attempts.Load() != 3 {
		t.Fatalf("dial attempts=%d", attempts.Load())
	}
}

func TestNoRetryAfterHelloSent(t *testing.T) {
	remote, backend := listen(t), listen(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s := newSession(ctx, cfg(t, remote.Addr().String(), backend.Addr().String()))
	defer s.close()
	var attempts atomic.Int32
	realDial := s.dial
	s.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		if addr == remote.Addr().String() {
			attempts.Add(1)
		}
		return realDial(ctx, addr)
	}
	go func() {
		raw, e := remote.Accept()
		if e != nil {
			return
		}
		raw.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1024)
		raw.Read(buf)
		raw.Close()
	}()
	s.openData(protocol.Message{Type: "open", Service: "ssh", ID: string(bytes.Repeat([]byte{'b'}, 64))}, func() {})
	if attempts.Load() != 1 {
		t.Fatalf("replayed sent hello: %d attempts", attempts.Load())
	}
}

func TestOpenDoesNotBlockHeartbeatDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newSession(ctx, cfg(t, "127.0.0.1:1", "127.0.0.1:2"))
	defer s.close()
	s.accepted = map[string]bool{"ssh": true}
	entered := make(chan struct{})
	s.dial = func(ctx context.Context, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	returned := make(chan struct{})
	go func() {
		s.handleMessage(protocol.Message{Type: "open", Service: "ssh", ID: string(bytes.Repeat([]byte{'c'}, 64))})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("control reader blocked in target dial")
	}
	<-entered
	cancel()
}

func TestControlLossClosesTargetAndData(t *testing.T) {
	remote, backend := listen(t), listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newSession(ctx, cfg(t, remote.Addr().String(), backend.Addr().String()))
	defer s.close()
	established := make(chan struct{})
	remoteDone := make(chan struct{})
	go func() {
		defer close(remoteDone)
		raw, e := remote.Accept()
		if e != nil {
			return
		}
		defer raw.Close()
		stream, _, e := protocol.ServerHandshake(ctx, raw, key(t), protocol.NewReplayCache(20))
		if e != nil {
			return
		}
		if protocol.WriteMessage(stream, protocol.Message{Type: "ready"}) != nil {
			return
		}
		close(established)
		io.Copy(io.Discard, stream)
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.openData(protocol.Message{Type: "open", Service: "ssh", ID: string(bytes.Repeat([]byte{'d'}, 64))}, func() {})
	}()
	target, e := backend.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	<-established
	cancel()
	wait(t, done)
	wait(t, remoteDone)
	target.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := target.Read(make([]byte, 1)); e != io.EOF {
		t.Fatalf("target retained: %v", e)
	}
}

func TestCancelStopsReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); Run(ctx, cfg(t, "127.0.0.1:1", "127.0.0.1:2")) }()
	cancel()
	wait(t, done)
}

func TestEstablishedConnectionsReleaseDialSlots(t *testing.T) {
	remote, backend := listen(t), listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newSession(ctx, cfg(t, remote.Addr().String(), backend.Addr().String()))
	defer s.close()
	s.tasks = make(chan struct{}, 1)
	s.accepted = map[string]bool{"ssh": true}
	ready := make(chan error, 2)
	keys := key(t)
	replay := protocol.NewReplayCache(20)
	go func() {
		for {
			raw, e := backend.Accept()
			if e != nil {
				return
			}
			go func() { defer raw.Close(); raw.Write([]byte{'#'}); io.Copy(io.Discard, raw) }()
		}
	}()
	go func() {
		for {
			raw, e := remote.Accept()
			if e != nil {
				return
			}
			go func() {
				defer raw.Close()
				stream, _, e := protocol.ServerHandshake(ctx, raw, keys, replay)
				if e == nil {
					e = protocol.WriteMessage(stream, protocol.Message{Type: "ready"})
				}
				if e == nil {
					var banner [1]byte
					_, e = io.ReadFull(stream, banner[:])
					if e == nil && banner[0] != '#' {
						e = errors.New("wrong backend banner")
					}
				}
				ready <- e
				if e == nil {
					<-ctx.Done()
				}
			}()
		}
	}()
	for _, id := range []string{string(bytes.Repeat([]byte{'a'}, 64)), string(bytes.Repeat([]byte{'b'}, 64))} {
		if e := s.handleMessage(protocol.Message{Type: "open", ID: id, Service: "ssh"}); e != nil {
			t.Fatal(e)
		}
		select {
		case e := <-ready:
			if e != nil {
				t.Fatal(e)
			}
		case m := <-s.out:
			t.Fatalf("active connection retained dial slot: %+v", m)
		case <-time.After(2 * time.Second):
			t.Fatal("new connection blocked behind established session")
		}
	}
}

func TestControlCloseWhileTargetDialReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newSession(ctx, cfg(t, "127.0.0.1:1", "127.0.0.1:2"))
	defer s.close()
	s.accepted = map[string]bool{"ssh": true}
	entered, release := make(chan struct{}), make(chan struct{})
	target, peer := net.Pipe()
	defer peer.Close()
	s.dial = func(context.Context, string) (net.Conn, error) { close(entered); <-release; return target, nil }
	if e := s.handleMessage(protocol.Message{Type: "open", ID: string(bytes.Repeat([]byte{'a'}, 64)), Service: "ssh"}); e != nil {
		t.Fatal(e)
	}
	<-entered
	cancel()
	s.tracker.Close()
	close(release)
	s.wg.Wait()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := peer.Read(make([]byte, 1)); e != io.EOF {
		t.Fatalf("dial-return race retained target: %v", e)
	}
}

func TestControlCloseDuringDataHandshake(t *testing.T) {
	remote, backend := listen(t), listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newSession(ctx, cfg(t, remote.Addr().String(), backend.Addr().String()))
	defer s.close()
	s.accepted = map[string]bool{"ssh": true}
	sent := make(chan struct{})
	remoteDone := make(chan struct{})
	go func() {
		defer close(remoteDone)
		raw, e := remote.Accept()
		if e != nil {
			return
		}
		defer raw.Close()
		var p [1024]byte
		raw.Read(p[:])
		close(sent)
		io.Copy(io.Discard, raw)
	}()
	if e := s.handleMessage(protocol.Message{Type: "open", ID: string(bytes.Repeat([]byte{'b'}, 64)), Service: "ssh"}); e != nil {
		t.Fatal(e)
	}
	target, e := backend.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	<-sent
	cancel()
	s.wg.Wait()
	wait(t, remoteDone)
	target.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := target.Read(make([]byte, 1)); e != io.EOF {
		t.Fatalf("incomplete handshake retained target: %v", e)
	}
}
