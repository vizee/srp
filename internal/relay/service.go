package relay

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

type serviceEvent struct {
	failed net.Listener
	err    error
}
type service struct {
	relay      *Relay
	name, addr string
	members    []*control
	event      chan serviceEvent
}

func (s *service) notify() {
	select {
	case s.event <- serviceEvent{}:
	default:
	}
}
func (s *service) wanted() bool {
	s.relay.mu.Lock()
	defer s.relay.mu.Unlock()
	return len(s.members) > 0
}

// All listener and ticker variables are local to this function. Accept receives
// its own arguments; only the atomic stopped value crosses the two goroutines.
func (s *service) manage(ctx context.Context) {
	var currListener net.Listener
	var stopped *atomic.Bool
	var ticker *time.Ticker
	var tick <-chan time.Time
	stopTicker := func() {
		if ticker != nil {
			ticker.Stop()
			ticker = nil
			tick = nil
		}
	}
	closeListener := func() {
		if currListener != nil {
			stopped.Store(true)
			stopped = nil
			currListener.Close()
			currListener = nil
		}
	}
	startTicker := func() {
		if ticker == nil {
			ticker = time.NewTicker(time.Second)
			tick = ticker.C
		}
	}
	defer func() { closeListener(); stopTicker() }()
	tryListen := func() {
		if currListener != nil {
			return
		}
		ln, err := s.relay.listen(ctx, "tcp", s.addr)
		if err != nil {
			s.relay.cfg.Logger.Printf("warning: service %s listen %s: %v; retry in 1s", s.name, s.addr, err)
			startTicker()
			return
		}
		if ctx.Err() != nil || !s.wanted() {
			ln.Close()
			stopTicker()
			return
		}
		currListener = ln
		stopped = new(atomic.Bool)
		stopTicker()
		s.relay.cfg.Logger.Printf("service %s listening on %s", s.name, ln.Addr())
		s.relay.wg.Add(1)
		go func(ln net.Listener, flag *atomic.Bool) { defer s.relay.wg.Done(); s.accept(ctx, ln, flag) }(ln, stopped)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.event:
			if event.failed != nil && event.failed == currListener {
				closeListener()
				s.relay.cfg.Logger.Printf("warning: service %s accept: %v", s.name, event.err)
				if s.wanted() {
					startTicker()
				}
			}
			if !s.wanted() {
				closeListener()
				stopTicker()
			} else if currListener == nil && ticker == nil {
				tryListen()
			}
		case <-tick:
			if !s.wanted() {
				closeListener()
				stopTicker()
			} else {
				tryListen()
			}
		}
	}
}
func (s *service) accept(ctx context.Context, ln net.Listener, stopped *atomic.Bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !stopped.Load() {
				select {
				case s.event <- serviceEvent{failed: ln, err: err}:
				case <-ctx.Done():
				}
			}
			return
		}
		if stopped.Load() {
			conn.Close()
			return
		}
		s.relay.handleUser(s, conn, stopped)
	}
}
