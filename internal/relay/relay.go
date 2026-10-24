// Package relay serves registered TCP services through expose control sessions.
package relay

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/vizee/srp/internal/protocol"
	"github.com/vizee/srp/internal/transport"
)

type Config struct {
	Keys     *protocol.Keys
	Services map[string]string
	Logger   *log.Logger
	Verbose  bool
}
type Relay struct {
	cfg        Config
	mu         sync.Mutex
	services   map[string]*service
	controls   map[*control]struct{}
	pending    map[string]*pending
	replay     *protocol.ReplayCache
	tracker    transport.Tracker
	wg         sync.WaitGroup
	handshakes chan struct{}
	ctx        context.Context
	listen     func(string, string) (net.Listener, error)
	pendingTTL time.Duration
}

func New(cfg Config) (*Relay, error) {
	if cfg.Keys == nil || len(cfg.Services) == 0 {
		return nil, errors.New("relay requires keys and services")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	r := &Relay{cfg: cfg, services: make(map[string]*service), controls: make(map[*control]struct{}), pending: make(map[string]*pending), replay: protocol.NewReplayCache(65536), handshakes: make(chan struct{}, 256), listen: net.Listen, pendingTTL: 15 * time.Second}
	for name, addr := range cfg.Services {
		r.services[name] = &service{relay: r, name: name, addr: addr, event: make(chan serviceEvent, 1)}
	}
	return r, nil
}
func (r *Relay) Serve(parent context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(parent)
	r.ctx = ctx
	stop := context.AfterFunc(ctx, func() { ln.Close(); r.tracker.Close() })
	defer func() { cancel(); ln.Close(); r.tracker.Close(); r.wg.Wait(); stop() }()
	for _, s := range r.services {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); s.manage(ctx) }()
	}
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case r.handshakes <- struct{}{}:
		default:
			raw.Close()
			continue
		}
		if !r.tracker.Add(raw) {
			<-r.handshakes
			return nil
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer raw.Close()
			defer r.tracker.Remove(raw)
			s, h, e := protocol.ServerHandshake(ctx, raw, r.cfg.Keys, r.replay)
			<-r.handshakes
			if e != nil {
				if r.cfg.Verbose {
					r.cfg.Logger.Printf("tunnel handshake failed: %v", e)
				}
				return
			}
			switch h.Type {
			case "control":
				r.serveControl(s, h)
			case "data":
				r.serveData(s, h)
			}
		}()
	}
}
func sendReady(s *protocol.Stream, m protocol.Message) error {
	s.SetWriteDeadline(time.Now().Add(time.Second))
	defer s.SetWriteDeadline(time.Time{})
	return protocol.WriteMessage(s, m)
}
