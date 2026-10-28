package expose

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/vizee/srp/internal/protocol"
)

type preflightPool struct {
	parent, refill context.Context
	cfg            Config
	dial           func(context.Context, string) (net.Conn, error)
	key            string
	mu             sync.Mutex
	idle           map[*preflightConn]struct{}
}

type preflightConn struct {
	stream   *protocol.Stream
	requests chan upgradeRequest
}

type upgradeRequest struct {
	ctx    context.Context
	id     string
	result chan upgradeResult
}

type upgradeResult struct {
	stream *protocol.Stream
	err    error
}

func newPreflightPool(parent, refill context.Context, cfg Config, dial func(context.Context, string) (net.Conn, error), key string, limit int, wg *sync.WaitGroup) *preflightPool {
	p := &preflightPool{parent: parent, refill: refill, cfg: cfg, dial: dial, key: key, idle: make(map[*preflightConn]struct{})}
	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for refill.Err() == nil {
				stream, err := p.connect()
				if err == nil {
					if p.runConn(stream) {
						continue
					}
				} else if cfg.Verbose && refill.Err() == nil {
					cfg.Logger.Printf("preflight connect failed: %v; retry in 1s", err)
				}
				if !waitContext(refill, time.Second) {
					return
				}
			}
		}()
	}
	return p
}

func (p *preflightPool) connect() (*protocol.Stream, error) {
	ctx, cancel := context.WithTimeout(p.refill, 5*time.Second)
	defer cancel()
	raw, err := p.dial(ctx, p.cfg.Remote)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	keep := false
	defer func() {
		stop()
		if !keep {
			raw.Close()
		}
	}()
	stream, err := protocol.ClientHandshake(ctx, raw, p.cfg.Keys, protocol.Hello{Type: "preflight", PreflightKey: p.key})
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	stream.SetReadDeadline(deadline)
	m, err := protocol.ReadMessage(stream)
	if err != nil {
		return nil, err
	}
	if m.Type != "ready" {
		return nil, errors.New("relay rejected preflight: " + m.Code)
	}
	stream.SetReadDeadline(time.Time{})
	keep = true
	return stream, nil
}

// runConn owns all idle IO. It hands ownership to data traffic only after the
// upgrade response, with no heartbeat reader/writer or idle deadline remaining.
func (p *preflightPool) runConn(stream *protocol.Stream) (handed bool) {
	c := &preflightConn{stream: stream, requests: make(chan upgradeRequest, 1)}
	stop := context.AfterFunc(p.parent, func() { stream.Close() })
	defer stop()
	defer func() {
		p.mu.Lock()
		delete(p.idle, c)
		p.mu.Unlock()
		if !handed {
			stream.Close()
		}
		// take enqueues under mu, before cleanup can remove the connection.
		select {
		case req := <-c.requests:
			req.result <- upgradeResult{err: errors.New("preflight closed before upgrade")}
		default:
		}
	}()
	p.mu.Lock()
	if p.refill.Err() == nil {
		p.idle[c] = struct{}{}
	}
	p.mu.Unlock()
	tick := time.NewTicker(protocol.HeartbeatInterval)
	defer tick.Stop()
	retired := p.refill.Done()
	for {
		select {
		case <-p.parent.Done():
			return false
		case <-retired:
			p.mu.Lock()
			delete(p.idle, c)
			p.mu.Unlock()
			retired = nil // Keep sending heartbeats until the relay rejects the old key.
		case req := <-c.requests:
			err := upgradePreflight(req.ctx, stream, req.id)
			stop()
			if err == nil {
				handed = true
			}
			req.result <- upgradeResult{stream: stream, err: err}
			return handed
		case <-tick.C:
			stream.SetWriteDeadline(time.Now().Add(time.Second))
			if protocol.WriteMessage(stream, protocol.Message{Type: "heartbeat", PreflightKey: p.key}) != nil {
				return false
			}
			stream.SetWriteDeadline(time.Time{})
			stream.SetReadDeadline(time.Now().Add(2 * protocol.HeartbeatInterval))
			m, err := protocol.ReadMessage(stream)
			stream.SetReadDeadline(time.Time{})
			if err != nil || m.Type != "heartbeat" || m.PreflightKey != p.key {
				return false
			}
		}
	}
}

func (p *preflightPool) take(ctx context.Context, id string) (*protocol.Stream, bool, error) {
	if p == nil {
		return nil, false, nil
	}
	p.mu.Lock()
	if p.refill.Err() != nil {
		p.mu.Unlock()
		return nil, false, nil
	}
	for c := range p.idle {
		delete(p.idle, c)
		req := upgradeRequest{ctx: ctx, id: id, result: make(chan upgradeResult, 1)}
		c.requests <- req
		p.mu.Unlock()
		stop := context.AfterFunc(ctx, func() { c.stream.Close() })
		result := <-req.result
		stop()
		return result.stream, true, result.err
	}
	p.mu.Unlock()
	return nil, false, nil
}

func upgradePreflight(ctx context.Context, stream *protocol.Stream, id string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	stream.SetDeadline(deadline)
	defer stream.SetDeadline(time.Time{})
	// Conservatively treat every attempted upgrade write as sent; never retry an
	// ID that the relay may already have consumed, including a lost ready response.
	if err := protocol.WriteMessage(stream, protocol.Message{Type: "upgrade", ID: id}); err != nil {
		return &protocol.HandshakeError{Sent: true, Err: err}
	}
	m, err := protocol.ReadMessage(stream)
	if err == nil && m.Type != "ready" {
		err = errors.New("relay rejected upgrade: " + m.Code)
	}
	if err != nil {
		return &protocol.HandshakeError{Sent: true, Err: err}
	}
	return nil
}
