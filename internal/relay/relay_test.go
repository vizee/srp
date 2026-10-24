package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
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
		r.listen = func(ctx context.Context, n, a string) (net.Listener, error) {
			calls.Add(1)
			return (&net.ListenConfig{}).Listen(ctx, n, a)
		}
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
		r.listen = func(ctx context.Context, n, a string) (net.Listener, error) {
			calls.Add(1)
			return (&net.ListenConfig{}).Listen(ctx, n, a)
		}
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
		r.listen = func(ctx context.Context, n, a string) (net.Listener, error) {
			calls.Add(1)
			return (&net.ListenConfig{}).Listen(ctx, n, a)
		}
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
		r.listen = func(ctx context.Context, n, a string) (net.Listener, error) {
			ln, e := (&net.ListenConfig{}).Listen(ctx, n, a)
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

func TestShutdownCancelsServiceDNS(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	oldResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return nil, errors.New("test resolver released")
		}
	}}
	defer func() { net.DefaultResolver = oldResolver }()
	defer close(release)
	r, e := New(Config{Keys: key(t), Services: map[string]string{"ssh": "shutdown-test.invalid:12345"}})
	if e != nil {
		t.Fatal(e)
	}
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, ln) }()
	control, _ := controlClient(t, ln.Addr().String(), "ssh")
	defer control.Close()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("DNS lookup did not start")
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Error("relay shutdown blocked in service DNS resolution")
	}
}

func TestUnauthenticatedDataCannotConsumePending(t *testing.T) {
	r, remote := start(t, map[string]string{"ssh": freeAddr(t)}, nil)
	control, _ := controlClient(t, remote, "ssh")
	await(t, func() bool { return memberCount(r, "ssh") == 1 })
	source, peer := net.Pipe()
	defer peer.Close()
	r.handleUser(r.services["ssh"], source, new(atomic.Bool))
	m, e := protocol.ReadMessage(control)
	if e != nil {
		t.Fatal(e)
	}
	wrong, _ := protocol.NewKeys(bytes.Repeat([]byte{3}, 32))
	for _, tc := range []struct {
		keys  *protocol.Keys
		hello protocol.Hello
	}{
		{wrong, protocol.Hello{Type: "data", ID: m.ID}},
		{key(t), protocol.Hello{Type: "data", ID: m.ID, TimestampMS: time.Now().Add(20 * time.Second).UnixMilli()}},
		{wrong, protocol.Hello{Type: "control", Services: []string{"ssh"}}},
	} {
		raw, e := net.Dial("tcp", remote)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, e = protocol.ClientHandshake(ctx, raw, tc.keys, tc.hello)
		raw.Close()
		cancel()
		if e == nil {
			t.Fatal("unauthenticated hello accepted")
		}
	}
	r.mu.Lock()
	_, exists := r.pending[m.ID]
	members := len(r.services["ssh"].members)
	r.mu.Unlock()
	if !exists || members != 1 {
		t.Fatal("failed authentication changed registration or consumed ID")
	}
	data, ready := dataClient(t, remote, m.ID)
	defer data.Close()
	if ready.Type != "ready" {
		t.Fatal("legitimate data lost pending ID")
	}
}

func TestBlockedReadyDoesNotParticipateInDispatch(t *testing.T) {
	r, remote := start(t, map[string]string{"ssh": freeAddr(t)}, nil)
	first, _ := controlClient(t, remote, "ssh")
	await(t, func() bool { return memberCount(r, "ssh") == 1 })
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		s, h, e := protocol.ServerHandshake(r.ctx, server, r.cfg.Keys, r.replay)
		if e == nil {
			r.serveControl(s, h)
		}
	}()
	second, e := protocol.ClientHandshake(r.ctx, client, r.cfg.Keys, protocol.Hello{Type: "control", Services: []string{"ssh"}})
	if e != nil {
		t.Fatal(e)
	}
	await(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return len(r.controls) == 2 })
	for i := 0; i < 2; i++ {
		source, peer := net.Pipe()
		defer peer.Close()
		r.handleUser(r.services["ssh"], source, new(atomic.Bool))
		first.SetReadDeadline(time.Now().Add(time.Second))
		m, e := protocol.ReadMessage(first)
		if e != nil || m.Type != "open" {
			t.Fatalf("blocked ready received work: %+v %v", m, e)
		}
	}
	second.SetReadDeadline(time.Now().Add(time.Second))
	m, e := protocol.ReadMessage(second)
	if e != nil || m.Type != "ready" {
		t.Fatalf("ready order: %+v %v", m, e)
	}
	await(t, func() bool { return memberCount(r, "ssh") == 2 })
	second.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("second control did not exit")
	}
}

func TestPendingClaimTimeoutAndControlCloseCompete(t *testing.T) {
	r, remote := start(t, map[string]string{"ssh": freeAddr(t)}, nil)
	for trial := 0; trial < 10; trial++ {
		control, _ := controlClient(t, remote, "ssh")
		await(t, func() bool { return memberCount(r, "ssh") == 1 })
		source, peer := net.Pipe()
		r.handleUser(r.services["ssh"], source, new(atomic.Bool))
		m, e := protocol.ReadMessage(control)
		if e != nil {
			t.Fatal(e)
		}
		r.mu.Lock()
		owner := r.pending[m.ID].owner
		r.mu.Unlock()
		gate := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(3)
		go func() { defer workers.Done(); <-gate; r.release(m.ID, owner) }()
		go func() { defer workers.Done(); <-gate; control.Close() }()
		go func() {
			defer workers.Done()
			<-gate
			raw, e := net.Dial("tcp", remote)
			if e != nil {
				return
			}
			defer raw.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			s, e := protocol.ClientHandshake(ctx, raw, r.cfg.Keys, protocol.Hello{Type: "data", ID: m.ID})
			if e != nil {
				return
			}
			s.SetReadDeadline(time.Now().Add(time.Second))
			ready, e := protocol.ReadMessage(s)
			if e == nil && ready.Type == "ready" {
				s.SetReadDeadline(time.Now().Add(time.Second))
				_, e := s.Read(make([]byte, 1))
				var timeout net.Error
				if e == nil || (errors.As(e, &timeout) && timeout.Timeout()) {
					t.Error("racing control close left data alive")
				}
			}
		}()
		close(gate)
		workers.Wait()
		peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, e := peer.Read(make([]byte, 1)); e != io.EOF {
			t.Fatalf("source not closed: %v", e)
		}
		peer.Close()
		await(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return len(r.pending) == 0 && len(r.controls) == 0 })
	}
}
