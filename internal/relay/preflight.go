package relay

import (
	"sync"
	"time"

	"github.com/vizee/srp/internal/protocol"
)

func (r *Relay) servePreflight(s *protocol.Stream, h protocol.Hello) {
	r.mu.Lock()
	c := r.preflightKeys[h.PreflightKey]
	code := ""
	if c == nil || c.ctx.Err() != nil {
		code = "invalid_preflight_key"
	} else if c.preflightCount >= r.cfg.MaxPreflightConns {
		code = "preflight_limit"
	} else {
		c.preflightCount++
	}
	r.mu.Unlock()
	if code != "" {
		sendReady(s, protocol.Message{Type: "error", Code: code})
		return
	}
	// Idle preflights deliberately belong to the relay process, not c.tracker.
	release := sync.OnceFunc(func() {
		r.mu.Lock()
		c.preflightCount--
		r.mu.Unlock()
	})
	defer release()
	lastHeartbeat := time.Now()
	if sendReady(s, protocol.Message{Type: "ready"}) != nil {
		return
	}
	for {
		s.SetReadDeadline(lastHeartbeat.Add(2 * protocol.HeartbeatInterval))
		m, err := protocol.ReadMessage(s)
		if err != nil {
			return
		}
		r.mu.Lock()
		valid := r.preflightKeys[h.PreflightKey] == c && c.ctx.Err() == nil
		r.mu.Unlock()
		if !valid || (m.Type == "heartbeat" && m.PreflightKey != h.PreflightKey) {
			sendReady(s, protocol.Message{Type: "error", Code: "invalid_preflight_key"})
			return
		}
		switch m.Type {
		case "heartbeat":
			lastHeartbeat = time.Now()
			if sendReady(s, protocol.Message{Type: "heartbeat", PreflightKey: h.PreflightKey}) != nil {
				return
			}
		case "upgrade":
			if !protocol.ValidID(m.ID) {
				sendReady(s, protocol.Message{Type: "error", Code: "invalid_data_id"})
				return
			}
			r.serveDataFor(s, m.ID, c, release)
			return
		default:
			sendReady(s, protocol.Message{Type: "error", Code: "invalid_preflight_message"})
			return
		}
	}
}
