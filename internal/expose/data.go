package expose

import (
	"context"
	"errors"
	"time"

	"github.com/vizee/srp/internal/protocol"
	"github.com/vizee/srp/internal/transport"
)

func (s *session) openData(m protocol.Message, releaseDialSlot func()) {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	target, err := s.dial(ctx, s.cfg.Targets[m.Service])
	if err != nil {
		s.cfg.Logger.Printf("target dial failed service=%s: %v", m.Service, err)
		s.report(m, "target_unreachable")
		return
	}
	if !s.tracker.Add(target) {
		return
	}
	defer func() { target.Close(); s.tracker.Remove(target) }()
	for ctx.Err() == nil {
		stream, err := s.connectData(ctx, m.ID)
		if err == nil {
			releaseDialSlot()
			cancel() // Connection budget is over; established traffic has no idle deadline.
			defer func() { stream.Close(); s.tracker.Remove(stream.Conn) }()
			transport.Bridge(s.ctx, stream, target)
			return
		}
		var he *protocol.HandshakeError
		if errors.As(err, &he) && he.Sent {
			s.cfg.Logger.Printf("data handshake failed service=%s: %v", m.Service, err)
			s.report(m, "data_handshake_failed")
			return
		}
		if s.cfg.Verbose {
			s.cfg.Logger.Printf("data connect failed service=%s: %v; retry in 1s", m.Service, err)
		}
		if !waitContext(ctx, time.Second) {
			break
		}
	}
	s.report(m, "data_connect_timeout")
}

func (s *session) connectData(ctx context.Context, id string) (stream *protocol.Stream, err error) {
	raw, err := s.dial(ctx, s.cfg.Remote)
	if err != nil {
		return nil, err
	}
	if !s.tracker.Add(raw) {
		return nil, s.ctx.Err()
	}
	keep := false
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer func() {
		stop()
		if !keep {
			raw.Close()
			s.tracker.Remove(raw)
		}
	}()
	stream, err = protocol.ClientHandshake(ctx, raw, s.cfg.Keys, protocol.Hello{Type: "data", ID: id})
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	stream.SetReadDeadline(deadline)
	ready, err := protocol.ReadMessage(stream)
	if err == nil && ready.Type != "ready" {
		err = errors.New("relay rejected data connection: " + ready.Code)
	}
	if err != nil {
		return nil, &protocol.HandshakeError{Sent: true, Err: err}
	}
	stream.SetReadDeadline(time.Time{})
	keep = true
	return stream, nil
}
