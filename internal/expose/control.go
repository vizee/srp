package expose

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/vizee/srp/internal/protocol"
	"github.com/vizee/srp/internal/transport"
)

type session struct {
	cfg      Config
	ctx      context.Context
	cancel   context.CancelFunc
	stop     func() bool
	tracker  transport.Tracker
	wg       sync.WaitGroup
	out      chan protocol.Message
	tasks    chan struct{}
	accepted map[string]bool
	dial     func(context.Context, string) (net.Conn, error)
}

func newSession(parent context.Context, cfg Config) *session {
	ctx, cancel := context.WithCancel(parent)
	s := &session{cfg: cfg, ctx: ctx, cancel: cancel, out: make(chan protocol.Message, 256), tasks: make(chan struct{}, 256), accepted: make(map[string]bool)}
	s.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	}
	s.stop = context.AfterFunc(ctx, s.tracker.Close)
	return s
}
func (s *session) close() { s.cancel(); s.tracker.Close(); s.wg.Wait(); s.stop() }
func (s *session) handleMessage(m protocol.Message) error {
	if m.Type != "open" || !protocol.ValidID(m.ID) || !s.accepted[m.Service] {
		return errors.New("invalid relay open request")
	}
	select {
	case s.tasks <- struct{}{}:
	default:
		s.report(m, "busy")
		return nil
	}
	s.wg.Add(1)
	go func() { defer s.wg.Done(); defer func() { <-s.tasks }(); s.openData(m) }()
	return nil
}
func (s *session) report(m protocol.Message, code string) {
	select {
	case s.out <- protocol.Message{Type: "open_error", ID: m.ID, Code: code}:
	default:
		s.cfg.Logger.Printf("warning: error queue full service=%s", m.Service)
	}
}
