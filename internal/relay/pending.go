package relay

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync/atomic"
	"time"

	"github.com/vizee/srp/internal/protocol"
	"github.com/vizee/srp/internal/transport"
)

type pending struct {
	id      string
	client  net.Conn
	owner   *control
	expires time.Time
	timer   *time.Timer
}

func (r *Relay) handleUser(s *service, client net.Conn, stopped *atomic.Bool) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		client.Close()
		return
	}
	id := hex.EncodeToString(random[:])
	r.mu.Lock()
	if stopped.Load() || len(s.members) == 0 || len(r.pending) >= 4096 {
		r.mu.Unlock()
		client.Close()
		return
	}
	c := s.members[0]
	copy(s.members, s.members[1:])
	s.members[len(s.members)-1] = c
	if !c.active || c.ctx.Err() != nil || c.pendingCount >= 256 {
		r.mu.Unlock()
		client.Close()
		return
	}
	if !c.tracker.Add(client) || !r.tracker.Add(client) {
		r.mu.Unlock()
		c.tracker.Remove(client)
		client.Close()
		return
	}
	p := &pending{id: id, client: client, owner: c, expires: time.Now().Add(r.pendingTTL)}
	r.pending[id] = p
	c.pendingCount++
	p.timer = time.AfterFunc(r.pendingTTL, func() { r.release(id, c) })
	select {
	case c.out <- protocol.Message{Type: "open", ID: id, Service: s.name}:
		r.mu.Unlock()
	default:
		r.mu.Unlock()
		r.cfg.Logger.Printf("warning: control queue full service=%s", s.name)
		r.release(id, c)
	}
}
func (r *Relay) release(id string, owner *control) {
	r.mu.Lock()
	p := r.pending[id]
	if p == nil || (owner != nil && p.owner != owner) {
		r.mu.Unlock()
		return
	}
	delete(r.pending, id)
	p.owner.pendingCount--
	p.timer.Stop()
	r.mu.Unlock()
	p.owner.tracker.Remove(p.client)
	r.tracker.Remove(p.client)
	p.client.Close()
}
func (r *Relay) serveData(s *protocol.Stream, h protocol.Hello) {
	r.serveDataFor(s, h.ID, nil, nil)
}

// owner is required for upgrades; a preflight cannot claim another control's ID.
func (r *Relay) serveDataFor(s *protocol.Stream, id string, owner *control, onClaim func()) {
	r.mu.Lock()
	p := r.pending[id]
	if p == nil || (owner != nil && (p.owner != owner || r.preflightKeys[owner.preflightKey] != owner)) || !p.owner.active || p.owner.ctx.Err() != nil || !time.Now().Before(p.expires) {
		r.mu.Unlock()
		sendReady(s, protocol.Message{Type: "error", Code: "invalid_data_id"})
		return
	}
	delete(r.pending, id)
	p.owner.pendingCount--
	p.timer.Stop()
	added := p.owner.tracker.Add(s)
	r.mu.Unlock()
	defer func() {
		s.Close()
		p.client.Close()
		p.owner.tracker.Remove(s)
		p.owner.tracker.Remove(p.client)
		r.tracker.Remove(p.client)
	}()
	if !added {
		return
	}
	if onClaim != nil {
		onClaim()
	}
	s.SetDeadline(time.Time{})
	if err := sendReady(s, protocol.Message{Type: "ready"}); err != nil {
		return
	}
	transport.Bridge(p.owner.ctx, s, p.client)
}
