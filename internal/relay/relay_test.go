package relay

import (
	"bytes"
	"context"
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
func freeAddr(t *testing.T) string {
	t.Helper()
	ln := listen(t)
	addr := ln.Addr().String()
	ln.Close()
	return addr
}
func await(t *testing.T, f func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}
func key(t *testing.T) *protocol.Keys {
	t.Helper()
	k, e := protocol.NewKeys(bytes.Repeat([]byte{9}, 32))
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func start(t *testing.T, services map[string]string, configure func(*Relay)) (*Relay, string) {
	t.Helper()
	r, e := New(Config{Keys: key(t), Services: services, Logger: log.New(io.Discard, "", 0)})
	if e != nil {
		t.Fatal(e)
	}
	if configure != nil {
		configure(r)
	}
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("relay shutdown leaked goroutines")
		}
	})
	return r, ln.Addr().String()
}
func controlClient(t *testing.T, addr string, names ...string) (*protocol.Stream, protocol.Message) {
	t.Helper()
	raw, e := net.Dial("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, e := protocol.ClientHandshake(ctx, raw, key(t), protocol.Hello{Type: "control", Services: names})
	if e != nil {
		t.Fatal(e)
	}
	s.SetReadDeadline(time.Now().Add(3 * time.Second))
	m, e := protocol.ReadMessage(s)
	if e != nil {
		t.Fatal(e)
	}
	return s, m
}
func dataClient(t *testing.T, addr, id string) (*protocol.Stream, protocol.Message) {
	t.Helper()
	raw, e := net.Dial("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, e := protocol.ClientHandshake(ctx, raw, key(t), protocol.Hello{Type: "data", ID: id})
	if e != nil {
		t.Fatal(e)
	}
	s.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, e := protocol.ReadMessage(s)
	if e != nil {
		t.Fatal(e)
	}
	return s, m
}
func memberCount(r *Relay, name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.services[name].members)
}

func TestServiceStartsIdle(t *testing.T) {
	addr := freeAddr(t)
	var calls atomic.Int32
	_, _ = start(t, map[string]string{"ssh": addr}, func(r *Relay) {
		r.listen = func(n, a string) (net.Listener, error) { calls.Add(1); return net.Listen(n, a) }
	})
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("listener created without registration")
	}
}
func TestBindFailureRetriesAndStops(t *testing.T) {
	occupied := listen(t)
	addr := occupied.Addr().String()
	var calls atomic.Int32
	r, remote := start(t, map[string]string{"ssh": addr}, func(r *Relay) {
		r.listen = func(n, a string) (net.Listener, error) { calls.Add(1); return net.Listen(n, a) }
	})
	c, m := controlClient(t, remote, "ssh")
	if m.Type != "ready" || len(m.Accepted) != 1 {
		t.Fatalf("registration depends on bind: %+v", m)
	}
	await(t, func() bool { return calls.Load() >= 1 })
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("retry ticker duplicated")
	}
	occupied.Close()
	await(t, func() bool {
		raw, e := net.DialTimeout("tcp", addr, 20*time.Millisecond)
		if e != nil {
			return false
		}
		raw.Close()
		return true
	})
	count := calls.Load()
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != count {
		t.Fatal("successful listener still retried")
	}
	c.Close()
	await(t, func() bool { return memberCount(r, "ssh") == 0 })
	await(t, func() bool {
		raw, e := net.DialTimeout("tcp", addr, 20*time.Millisecond)
		if e == nil {
			raw.Close()
		}
		return e != nil
	})
}
func TestStopDuringRetry(t *testing.T) {
	occupied := listen(t)
	var calls atomic.Int32
	r, remote := start(t, map[string]string{"ssh": occupied.Addr().String()}, func(r *Relay) {
		r.listen = func(n, a string) (net.Listener, error) { calls.Add(1); return net.Listen(n, a) }
	})
	c, _ := controlClient(t, remote, "ssh")
	await(t, func() bool { return calls.Load() > 0 })
	c.Close()
	await(t, func() bool { return memberCount(r, "ssh") == 0 })
	time.Sleep(50 * time.Millisecond)
	n := calls.Load()
	time.Sleep(1100 * time.Millisecond)
	if calls.Load() != n {
		t.Fatal("stopped service kept retrying")
	}
}
func TestIndependentRoundRobinAndReadyBeforeOpen(t *testing.T) {
	r, remote := start(t, map[string]string{"ssh": freeAddr(t), "web": freeAddr(t)}, nil)
	c1, m := controlClient(t, remote, "ssh", "web", "ignored")
	if m.Type != "ready" || len(m.Ignored) != 1 {
		t.Fatalf("%+v", m)
	}
	c2, _ := controlClient(t, remote, "ssh", "web")
	await(t, func() bool { return memberCount(r, "ssh") == 2 })
	for _, name := range []string{"ssh", "web"} {
		for i := 0; i < 4; i++ {
			source, peer := net.Pipe()
			defer peer.Close()
			r.handleUser(r.services[name], source, new(atomic.Bool))
			chosen := c1
			if i%2 == 1 {
				chosen = c2
			}
			chosen.SetReadDeadline(time.Now().Add(time.Second))
			m, e := protocol.ReadMessage(chosen)
			if e != nil || m.Type != "open" || m.Service != name || !protocol.ValidID(m.ID) {
				t.Fatalf("%s round %d: %+v %v", name, i, m, e)
			}
		}
	}
}
func TestPendingSingleClaimAndControlClose(t *testing.T) {
	r, remote := start(t, map[string]string{"ssh": freeAddr(t)}, nil)
	c, _ := controlClient(t, remote, "ssh")
	await(t, func() bool { return memberCount(r, "ssh") == 1 })
	source, peer := net.Pipe()
	defer peer.Close()
	r.handleUser(r.services["ssh"], source, new(atomic.Bool))
	m, e := protocol.ReadMessage(c)
	if e != nil {
		t.Fatal(e)
	}
	data, ready := dataClient(t, remote, m.ID)
	if ready.Type != "ready" {
		t.Fatalf("%+v", ready)
	}
	duplicate, rejected := dataClient(t, remote, m.ID)
	duplicate.Close()
	if rejected.Type != "error" {
		t.Fatal("ID accepted twice")
	}
	c.Close()
	data.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := data.Read(make([]byte, 1)); e == nil {
		t.Fatal("control close retained data")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := peer.Read(make([]byte, 1)); e != io.EOF {
		t.Fatalf("source retained: %v", e)
	}
}
func TestPendingTimeoutRejectsLateData(t *testing.T) {
	r, remote := start(t, map[string]string{"ssh": freeAddr(t)}, func(r *Relay) { r.pendingTTL = 30 * time.Millisecond })
	c, _ := controlClient(t, remote, "ssh")
	await(t, func() bool { return memberCount(r, "ssh") == 1 })
	source, peer := net.Pipe()
	defer peer.Close()
	r.handleUser(r.services["ssh"], source, new(atomic.Bool))
	m, e := protocol.ReadMessage(c)
	if e != nil {
		t.Fatal(e)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := peer.Read(make([]byte, 1)); e != io.EOF {
		t.Fatal(e)
	}
	data, rejected := dataClient(t, remote, m.ID)
	data.Close()
	if rejected.Type != "error" {
		t.Fatal("late ID accepted")
	}
}

type delayedAcceptListener struct {
	net.Listener
	gate <-chan struct{}
}

func (l *delayedAcceptListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		<-l.gate
	}
	return c, e
}

func TestDuplicateStartAndOldAcceptCannotStopNewListener(t *testing.T) {
	addr := freeAddr(t)
	gate := make(chan struct{})
	var released atomic.Bool
	defer func() {
		if released.CompareAndSwap(false, true) {
			close(gate)
		}
	}()
	var calls atomic.Int32
	r, remote := start(t, map[string]string{"ssh": addr}, func(r *Relay) {
		r.listen = func(n, a string) (net.Listener, error) {
			ln, e := net.Listen(n, a)
			if calls.Add(1) == 1 && e == nil {
				return &delayedAcceptListener{Listener: ln, gate: gate}, nil
			}
			return ln, e
		}
	})
	c1, _ := controlClient(t, remote, "ssh")
	await(t, func() bool { return calls.Load() == 1 })
	for i := 0; i < 20; i++ {
		r.services["ssh"].notify()
	}
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("duplicate start created another listener")
	}
	c1.Close()
	await(t, func() bool { return memberCount(r, "ssh") == 0 })
	c2, _ := controlClient(t, remote, "ssh")
	await(t, func() bool { return calls.Load() >= 2 })
	if released.CompareAndSwap(false, true) {
		close(gate)
	}
	raw, e := net.DialTimeout("tcp", addr, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	c2.SetReadDeadline(time.Now().Add(time.Second))
	m, e := protocol.ReadMessage(c2)
	if e != nil || m.Type != "open" {
		t.Fatalf("new listener broken by old accept: %+v %v", m, e)
	}
}

func TestUnknownServicesDoNotRegister(t *testing.T) {
	r, remote := start(t, map[string]string{"ssh": freeAddr(t)}, nil)
	c, m := controlClient(t, remote, "other")
	defer c.Close()
	if m.Type != "error" || m.Code != "no_matching_services" {
		t.Fatalf("%+v", m)
	}
	if memberCount(r, "ssh") != 0 {
		t.Fatal("unknown service registered")
	}
}

func TestRapidMembershipChanges(t *testing.T) {
	r, remote := start(t, map[string]string{"ssh": freeAddr(t)}, nil)
	for i := 0; i < 10; i++ {
		c, _ := controlClient(t, remote, "ssh")
		c.Close()
	}
	await(t, func() bool { return memberCount(r, "ssh") == 0 })
	r.mu.Lock()
	n := len(r.pending)
	r.mu.Unlock()
	if n != 0 {
		t.Fatalf("pending requests leaked: %d", n)
	}
}
