// Package expose connects local TCP targets to a relay without disclosing
// target addresses on the control or data protocol.
package expose

import (
	"context"
	"errors"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/vizee/srp/internal/protocol"
)

type Config struct {
	Keys    *protocol.Keys
	Remote  string
	Targets map[string]string
	Logger  *log.Logger
	Verbose bool
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.Keys == nil || cfg.Remote == "" || len(cfg.Targets) == 0 {
		return errors.New("expose requires keys, relay address and targets")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	targets := make(map[string]string, len(cfg.Targets))
	for name, addr := range cfg.Targets {
		targets[name] = addr
	}
	cfg.Targets = targets
	var pools sync.WaitGroup
	defer pools.Wait()
	backoff := time.Second
	for ctx.Err() == nil {
		stable, err := runSession(ctx, cfg, &pools)
		if ctx.Err() != nil {
			return nil
		}
		cfg.Logger.Printf("relay connection closed: %v; reconnect in %s", err, backoff)
		if stable >= 30*time.Second {
			backoff = time.Second
		}
		delay := backoff + time.Duration(rand.Int64N(int64(backoff/5)))
		if !waitContext(ctx, delay) {
			return nil
		}
		backoff = min(backoff*2, 10*time.Second)
	}
	return nil
}

func runSession(parent context.Context, cfg Config, pools *sync.WaitGroup) (time.Duration, error) {
	s := newSession(parent, cfg)
	defer s.close()
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(s.ctx, "tcp", cfg.Remote)
	if err != nil {
		return 0, err
	}
	if !s.tracker.Add(raw) {
		return 0, s.ctx.Err()
	}
	names := make([]string, 0, len(cfg.Targets))
	for name := range cfg.Targets {
		names = append(names, name)
	}
	sort.Strings(names)
	stream, err := protocol.ClientHandshake(s.ctx, raw, cfg.Keys, protocol.Hello{Type: "control", Services: names})
	if err != nil {
		return 0, err
	}
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	ready, err := protocol.ReadMessage(stream)
	stream.SetReadDeadline(time.Time{})
	if err != nil {
		return 0, err
	}
	if ready.Type != "ready" || len(ready.Accepted) == 0 {
		return 0, errors.New("relay rejected service registration: " + ready.Code)
	}
	seen := make(map[string]bool)
	for _, name := range ready.Accepted {
		if _, ok := cfg.Targets[name]; !ok || seen[name] {
			return 0, errors.New("invalid accepted services")
		}
		seen[name] = true
		s.accepted[name] = true
	}
	for _, name := range ready.Ignored {
		if _, ok := cfg.Targets[name]; !ok || seen[name] {
			return 0, errors.New("invalid ignored services")
		}
		seen[name] = true
	}
	if len(seen) != len(names) {
		return 0, errors.New("incomplete service registration response")
	}
	if !protocol.ValidID(ready.PreflightKey) || ready.MaxPreflightConns < 1 || ready.MaxPreflightConns > protocol.LimitMaxPreflightConns {
		return 0, errors.New("invalid preflight registration response")
	}
	s.pool = newPreflightPool(parent, s.ctx, cfg, s.dial, ready.PreflightKey, ready.MaxPreflightConns, pools)
	cfg.Logger.Printf("services registered accepted=%v ignored=%v", ready.Accepted, ready.Ignored)
	activeAt := time.Now()
	err = protocol.RunControl(s.ctx, stream, s.out, s.handleMessage)
	return time.Since(activeAt), err
}

func waitContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
