package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/vizee/srp/internal/protocol"
	"github.com/vizee/srp/internal/transport"
)

type control struct {
	stream         *protocol.Stream
	ctx            context.Context
	cancel         context.CancelFunc
	out            chan protocol.Message
	tracker        transport.Tracker
	names          []string
	active         bool // guarded by relay.mu
	pendingCount   int  // guarded by relay.mu
	preflightKey   string
	preflightCount int // guarded by relay.mu
}

func (r *Relay) serveControl(s *protocol.Stream, h protocol.Hello) {
	ctx, cancel := context.WithCancel(r.ctx)
	c := &control{stream: s, ctx: ctx, cancel: cancel, out: make(chan protocol.Message, 256)}
	c.tracker.Add(s)
	defer r.removeControl(c)
	var ignored []string
	for _, name := range h.Services {
		if _, ok := r.services[name]; ok {
			c.names = append(c.names, name)
		} else {
			ignored = append(ignored, name)
		}
	}
	sort.Strings(c.names)
	sort.Strings(ignored)
	if len(c.names) == 0 {
		sendReady(s, protocol.Message{Type: "error", Code: "no_matching_services"})
		return
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return
	}
	c.preflightKey = hex.EncodeToString(key[:])
	r.mu.Lock()
	r.controls[c] = struct{}{}
	r.preflightKeys[c.preflightKey] = c
	r.mu.Unlock()
	if err := sendReady(s, protocol.Message{Type: "ready", Accepted: c.names, Ignored: ignored, PreflightKey: c.preflightKey, MaxPreflightConns: r.cfg.MaxPreflightConns}); err != nil {
		return
	}
	r.mu.Lock()
	if ctx.Err() != nil {
		r.mu.Unlock()
		return
	}
	c.active = true
	for _, name := range c.names {
		r.services[name].members = append(r.services[name].members, c)
	}
	r.mu.Unlock()
	for _, name := range c.names {
		r.services[name].notify()
	}
	r.cfg.Logger.Printf("expose registered services=%v ignored=%v", c.names, ignored)
	err := protocol.RunControl(ctx, s, c.out, func(m protocol.Message) error {
		if m.Type != "open_error" || !protocol.ValidID(m.ID) {
			return errors.New("unexpected expose control message")
		}
		r.release(m.ID, c)
		r.cfg.Logger.Printf("service connection failed id=%s reason=%s", m.ID, m.Code)
		return nil
	})
	if ctx.Err() == nil && r.ctx.Err() == nil {
		r.cfg.Logger.Printf("expose control closed: %v", err)
	}
}
func (r *Relay) removeControl(c *control) {
	c.cancel()
	r.mu.Lock()
	c.active = false
	delete(r.controls, c)
	delete(r.preflightKeys, c.preflightKey)
	for _, name := range c.names {
		s := r.services[name]
		for i, member := range s.members {
			if member == c {
				s.members = append(s.members[:i], s.members[i+1:]...)
				break
			}
		}
	}
	for id, p := range r.pending {
		if p.owner == c {
			delete(r.pending, id)
			p.timer.Stop()
			r.tracker.Remove(p.client)
		}
	}
	c.pendingCount = 0
	r.mu.Unlock()
	c.tracker.Close()
	for _, name := range c.names {
		r.services[name].notify()
	}
}
