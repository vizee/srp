package protocol

import (
	"container/heap"
	"errors"
	"sync"
	"time"
)

type replayEntry struct {
	nonce   [24]byte
	expires time.Time
}
type expiryQueue []replayEntry

func (q expiryQueue) Len() int           { return len(q) }
func (q expiryQueue) Less(i, j int) bool { return q[i].expires.Before(q[j].expires) }
func (q expiryQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *expiryQueue) Push(v any)        { *q = append(*q, v.(replayEntry)) }
func (q *expiryQueue) Pop() any          { a := *q; v := a[len(a)-1]; *q = a[:len(a)-1]; return v }

// ReplayCache is shared by all tunnel connections of one relay process.
type ReplayCache struct {
	mu     sync.Mutex
	limit  int
	seen   map[[24]byte]struct{}
	expiry expiryQueue
}

func NewReplayCache(limit int) *ReplayCache {
	return &ReplayCache{limit: limit, seen: make(map[[24]byte]struct{})}
}
func (c *ReplayCache) accept(nonce [24]byte, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.expiry) > 0 && !c.expiry[0].expires.After(now) {
		e := heap.Pop(&c.expiry).(replayEntry)
		delete(c.seen, e.nonce)
	}
	if _, ok := c.seen[nonce]; ok {
		return errors.New("repeated handshake nonce")
	}
	if len(c.seen) >= c.limit {
		return errors.New("handshake nonce capacity reached")
	}
	c.seen[nonce] = struct{}{}
	heap.Push(&c.expiry, replayEntry{nonce: nonce, expires: now.Add(20 * time.Second)})
	return nil
}
