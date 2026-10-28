package relay

import (
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vizee/srp/internal/protocol"
)

type heartbeatDeadlineConn struct {
	net.Conn
	armed     atomic.Bool
	deadlines chan time.Time
	writes    chan time.Time
}

func (c *heartbeatDeadlineConn) SetReadDeadline(deadline time.Time) error {
	c.deadlines <- deadline
	return c.Conn.SetReadDeadline(deadline)
}

func (c *heartbeatDeadlineConn) Write(b []byte) (int, error) {
	if c.armed.Load() {
		c.writes <- time.Now()
		time.Sleep(100 * time.Millisecond)
	}
	return c.Conn.Write(b)
}

func TestPreflightTimeoutStartsAtHeartbeatReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { server.Close(); client.Close() })
	defer stop()
	wrapped := &heartbeatDeadlineConn{Conn: server, deadlines: make(chan time.Time, 8), writes: make(chan time.Time, 1)}
	keys := key(t)
	preflightKey := strings.Repeat("d", 64)
	r, err := New(Config{Keys: keys, Services: map[string]string{"ssh": ":22"}})
	if err != nil {
		t.Fatal(err)
	}
	c := &control{ctx: ctx, preflightKey: preflightKey}
	r.preflightKeys[preflightKey] = c
	go func() {
		stream, h, err := protocol.ServerHandshake(ctx, wrapped, keys, protocol.NewReplayCache(20))
		if err == nil {
			r.servePreflight(stream, h)
		}
	}()
	p, err := protocol.ClientHandshake(ctx, client, keys, protocol.Hello{Type: "preflight", PreflightKey: preflightKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = protocol.ReadMessage(p); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wrapped.deadlines:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	wrapped.armed.Store(true)
	if err = protocol.WriteMessage(p, protocol.Message{Type: "heartbeat", PreflightKey: preflightKey}); err != nil {
		t.Fatal(err)
	}
	if _, err = protocol.ReadMessage(p); err != nil {
		t.Fatal(err)
	}
	var writeStarted, deadline time.Time
	select {
	case writeStarted = <-wrapped.writes:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case deadline = <-wrapped.deadlines:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if deadline.After(writeStarted.Add(2*protocol.HeartbeatInterval + 20*time.Millisecond)) {
		t.Fatalf("response write extended heartbeat deadline by %s", deadline.Sub(writeStarted.Add(2*protocol.HeartbeatInterval)))
	}
}

func preflightClient(t *testing.T, addr, preflightKey string) (*protocol.Stream, protocol.Message) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	s, err := protocol.ClientHandshake(context.Background(), raw, key(t), protocol.Hello{Type: "preflight", PreflightKey: preflightKey})
	if err != nil {
		t.Fatal(err)
	}
	s.SetDeadline(time.Now().Add(2 * time.Second))
	m, err := protocol.ReadMessage(s)
	if err != nil {
		t.Fatal(err)
	}
	s.SetDeadline(time.Time{})
	return s, m
}

func preflightExchange(t *testing.T, s *protocol.Stream, m protocol.Message) protocol.Message {
	t.Helper()
	s.SetDeadline(time.Now().Add(time.Second))
	if err := protocol.WriteMessage(s, m); err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ReadMessage(s)
	if err != nil {
		t.Fatal(err)
	}
	s.SetDeadline(time.Time{})
	return got
}

func TestPreflightAdmissionAndKeyLifetime(t *testing.T) {
	r, remote := start(t, map[string]string{"ssh": freeAddr(t)}, func(r *Relay) { r.cfg.MaxPreflightConns = 1 })
	c, ready := controlClient(t, remote, "ssh")
	_, other := controlClient(t, remote, "ssh")
	if !protocol.ValidID(ready.PreflightKey) || ready.PreflightKey == other.PreflightKey || ready.MaxPreflightConns != 1 {
		t.Fatalf("bad metadata: %+v %+v", ready, other)
	}
	p, m := preflightClient(t, remote, ready.PreflightKey)
	if m.Type != "ready" {
		t.Fatal(m)
	}
	_, m = preflightClient(t, remote, ready.PreflightKey)
	if m.Code != "preflight_limit" {
		t.Fatal(m)
	}
	_, m = preflightClient(t, remote, strings.Repeat("0", 64))
	if m.Code != "invalid_preflight_key" {
		t.Fatal(m)
	}
	if got := preflightExchange(t, p, protocol.Message{Type: "heartbeat", PreflightKey: ready.PreflightKey}); got.Type != "heartbeat" || got.PreflightKey != ready.PreflightKey {
		t.Fatal(got)
	}
	c.Close()
	await(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.preflightKeys[ready.PreflightKey] == nil })
	// Control removal must leave idle sockets alone until the next heartbeat.
	p.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	var b [1]byte
	if _, err := p.Conn.Read(b[:]); err == nil {
		t.Fatal("unexpected idle bytes")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("idle preflight closed proactively: %v", err)
	}
	p.SetReadDeadline(time.Time{})
	if got := preflightExchange(t, p, protocol.Message{Type: "heartbeat", PreflightKey: ready.PreflightKey}); got.Code != "invalid_preflight_key" {
		t.Fatal(got)
	}
	p.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := protocol.ReadMessage(p); err == nil {
		t.Fatal("released key retained socket")
	}
}

func TestPreflightUpgradeOwnerAndSingleClaim(t *testing.T) {
	r, remote := start(t, map[string]string{"ssh": freeAddr(t)}, func(r *Relay) { r.cfg.MaxPreflightConns = 1 })
	c1, ready1 := controlClient(t, remote, "ssh")
	c2, ready2 := controlClient(t, remote, "ssh")
	await(t, func() bool { return memberCount(r, "ssh") == 2 })
	source, peer := net.Pipe()
	defer peer.Close()
	r.handleUser(r.services["ssh"], source, new(atomic.Bool))
	open, err := protocol.ReadMessage(c1)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := preflightClient(t, remote, ready2.PreflightKey)
	if got := preflightExchange(t, wrong, protocol.Message{Type: "upgrade", ID: open.ID}); got.Code != "invalid_data_id" {
		t.Fatal(got)
	}
	p, _ := preflightClient(t, remote, ready1.PreflightKey)
	// A heartbeat immediately before upgrade must not leak into data traffic.
	preflightExchange(t, p, protocol.Message{Type: "heartbeat", PreflightKey: ready1.PreflightKey})
	if got := preflightExchange(t, p, protocol.Message{Type: "upgrade", ID: open.ID}); got.Type != "ready" {
		t.Fatal(got)
	}
	replacement, m := preflightClient(t, remote, ready1.PreflightKey)
	if m.Type != "ready" {
		t.Fatalf("upgrade retained idle slot: %+v", m)
	}
	if got := preflightExchange(t, replacement, protocol.Message{Type: "upgrade", ID: open.ID}); got.Code != "invalid_data_id" {
		t.Fatal(got)
	}
	go func() { peer.Write([]byte("banner")); peer.Close() }()
	p.SetReadDeadline(time.Now().Add(time.Second))
	got, err := io.ReadAll(p)
	if err != nil || string(got) != "banner" {
		t.Fatalf("%q %v", got, err)
	}
	p.CloseWrite()
	c2.Close()
}

func TestPreflightHeartbeatRejectsWrongKey(t *testing.T) {
	_, remote := start(t, map[string]string{"ssh": freeAddr(t)}, nil)
	_, ready := controlClient(t, remote, "ssh")
	p, _ := preflightClient(t, remote, ready.PreflightKey)
	if got := preflightExchange(t, p, protocol.Message{Type: "heartbeat", PreflightKey: strings.Repeat("0", 64)}); got.Code != "invalid_preflight_key" {
		t.Fatal(got)
	}
}

func TestPreflightHeartbeatTimeout(t *testing.T) {
	t.Parallel()
	_, remote := start(t, map[string]string{"ssh": freeAddr(t)}, nil)
	_, ready := controlClient(t, remote, "ssh")
	p, _ := preflightClient(t, remote, ready.PreflightKey)
	started := time.Now()
	p.SetReadDeadline(started.Add(12 * time.Second))
	_, err := protocol.ReadMessage(p)
	if err == nil {
		t.Fatal("silent preflight retained")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("relay did not enforce timeout")
	}
	if time.Since(started) < 2*protocol.HeartbeatInterval-200*time.Millisecond {
		t.Fatal("preflight timeout shorter than two heartbeat intervals")
	}
}
