package expose

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vizee/srp/internal/protocol"
)

func awaitPool(t *testing.T, p *preflightPool, n int) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		p.mu.Lock()
		count := len(p.idle)
		p.mu.Unlock()
		if count == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pool did not reach %d idle connections", n)
}

func TestPreflightPoolUpgradeAndRefill(t *testing.T) {
	remote := listen(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newSession(parent, cfg(t, remote.Addr().String(), "127.0.0.1:1"))
	defer s.close()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	preflightKey := strings.Repeat("a", 64)
	seen := make(chan protocol.Hello, 4)
	upgraded := make(chan protocol.Message, 1)
	keys := key(t)
	go func() {
		for {
			raw, err := remote.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				stream, h, err := protocol.ServerHandshake(parent, raw, keys, protocol.NewReplayCache(20))
				if err != nil {
					return
				}
				seen <- h
				if protocol.WriteMessage(stream, protocol.Message{Type: "ready"}) != nil {
					return
				}
				for {
					m, err := protocol.ReadMessage(stream)
					if err != nil {
						return
					}
					if m.Type == "upgrade" {
						upgraded <- m
						protocol.WriteMessage(stream, protocol.Message{Type: "ready"})
						stream.Write([]byte("banner"))
						stream.CloseWrite()
						io.Copy(io.Discard, stream)
						return
					}
					protocol.WriteMessage(stream, m)
				}
			}()
		}
	}()
	s.pool = newPreflightPool(parent, s.ctx, s.cfg, s.dial, preflightKey, 1, &workers)
	awaitPool(t, s.pool, 1)
	id := strings.Repeat("b", 64)
	ctx, stop := context.WithTimeout(parent, 2*time.Second)
	defer stop()
	stream, err := s.connectData(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if m := <-upgraded; m.ID != id {
		t.Fatal(m)
	}
	stream.SetReadDeadline(time.Now().Add(time.Second))
	got, err := io.ReadAll(stream)
	if err != nil || string(got) != "banner" {
		t.Fatalf("%q %v", got, err)
	}
	stream.CloseWrite()
	awaitPool(t, s.pool, 1)
	for i := 0; i < 2; i++ {
		select {
		case h := <-seen:
			if h.Type != "preflight" || h.PreflightKey != preflightKey {
				t.Fatal(h)
			}
		case <-time.After(time.Second):
			t.Fatal("pool was not refilled")
		}
	}
	select {
	case h := <-seen:
		t.Fatalf("pool exceeded limit: %+v", h)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestPreflightOutlivesControlUntilHeartbeatFailure(t *testing.T) {
	t.Parallel()
	remote := listen(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newSession(parent, cfg(t, remote.Addr().String(), "127.0.0.1:1"))
	defer s.close()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	preflightKey := strings.Repeat("c", 64)
	requests := make(chan protocol.Message, 1)
	done := make(chan struct{})
	keys := key(t)
	go func() {
		defer close(done)
		raw, err := remote.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		stream, _, err := protocol.ServerHandshake(parent, raw, keys, protocol.NewReplayCache(20))
		if err != nil {
			return
		}
		protocol.WriteMessage(stream, protocol.Message{Type: "ready"})
		m, err := protocol.ReadMessage(stream)
		if err != nil {
			return
		}
		requests <- m
		protocol.WriteMessage(stream, protocol.Message{Type: "error", Code: "invalid_preflight_key"})
		io.Copy(io.Discard, stream)
	}()
	s.pool = newPreflightPool(parent, s.ctx, s.cfg, s.dial, preflightKey, 1, &workers)
	awaitPool(t, s.pool, 1)
	s.close()
	select {
	case m := <-requests:
		if m.Type != "heartbeat" || m.PreflightKey != preflightKey {
			t.Fatal(m)
		}
	case <-done:
		t.Fatal("control cleanup proactively closed preflight")
	case <-time.After(protocol.HeartbeatInterval + 2*time.Second):
		t.Fatal("no heartbeat")
	}
	wait(t, done)
}
