package transport

import (
	"net"
	"sync"
)

// Tracker serializes adding a connection against closing its owning scope.
// Closed scopes cannot acquire new connections, including in-flight dials.
type Tracker struct {
	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
}

func (t *Tracker) Add(c net.Conn) bool {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		c.Close()
		return false
	}
	if t.conns == nil {
		t.conns = make(map[net.Conn]struct{})
	}
	t.conns[c] = struct{}{}
	t.mu.Unlock()
	return true
}
func (t *Tracker) Remove(c net.Conn) { t.mu.Lock(); delete(t.conns, c); t.mu.Unlock() }
func (t *Tracker) Close() {
	t.mu.Lock()
	t.closed = true
	conns := t.conns
	t.conns = nil
	t.mu.Unlock()
	for c := range conns {
		c.Close()
	}
}
