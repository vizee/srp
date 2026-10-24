package protocol

import (
	"context"
	"time"
)

const HeartbeatInterval = 5 * time.Second
const HeartbeatTimeout = 7 * time.Second

// RunControl owns the sole control reader and writer. Application callbacks
// must dispatch slow work asynchronously so heartbeats remain independent.
func RunControl(parent context.Context, s *Stream, out <-chan Message, handle func(Message) error) error {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(ctx, func() { s.Close() })
	writerDone := make(chan struct{})
	defer func() { cancel(); s.Close(); <-writerDone; stop() }()
	go func() {
		defer close(writerDone)
		defer cancel()
		tick := time.NewTicker(HeartbeatInterval)
		defer tick.Stop()
		send := func(m Message) bool {
			s.SetWriteDeadline(time.Now().Add(time.Second))
			err := WriteMessage(s, m)
			s.SetWriteDeadline(time.Time{})
			return err == nil
		}
		for {
			// Service requests cannot starve a heartbeat already due.
			select {
			case <-tick.C:
				if !send(Message{Type: "heartbeat"}) {
					return
				}
			default:
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if !send(Message{Type: "heartbeat"}) {
					return
				}
			case m := <-out:
				if !send(m) {
					return
				}
			}
		}
	}()
	lastHeartbeat := time.Now()
	for {
		s.SetReadDeadline(lastHeartbeat.Add(HeartbeatTimeout))
		m, err := ReadMessage(s)
		if err != nil {
			return err
		}
		if m.Type == "heartbeat" {
			lastHeartbeat = time.Now()
			continue
		}
		if err := handle(m); err != nil {
			return err
		}
	}
}
