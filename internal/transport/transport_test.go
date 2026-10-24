package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func pair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	c, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	s, e := ln.Accept()
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []net.Conn{c, s} {
		t.Cleanup(func() { p.Close() })
		p.SetDeadline(time.Now().Add(5 * time.Second))
	}
	return c.(*net.TCPConn), s.(*net.TCPConn)
}
func TestBridgeHalfClose(t *testing.T) {
	client, a := pair(t)
	b, server := pair(t)
	done := make(chan struct{})
	go func() { Bridge(context.Background(), a, b); close(done) }()
	client.Write([]byte("request"))
	client.CloseWrite()
	req, e := io.ReadAll(server)
	if e != nil || string(req) != "request" {
		t.Fatalf("%q %v", req, e)
	}
	response := bytes.Repeat([]byte("response"), 32768)
	go func() { server.Write(response); server.CloseWrite() }()
	got, e := io.ReadAll(client)
	if e != nil || !bytes.Equal(got, response) {
		t.Fatalf("got %d: %v", len(got), e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bridge retained closed connection")
	}
}
func TestBridgeServerFirst(t *testing.T) {
	client, a := pair(t)
	b, server := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Bridge(ctx, a, b)
	server.Write([]byte("banner"))
	got := make([]byte, 6)
	if _, e := io.ReadFull(client, got); e != nil || string(got) != "banner" {
		t.Fatalf("%s %v", got, e)
	}
}
func TestBridgeCancellation(t *testing.T) {
	a, peerA := net.Pipe()
	b, peerB := net.Pipe()
	defer peerA.Close()
	defer peerB.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Bridge(ctx, a, b); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close blocked copies")
	}
}
func TestTrackerAddAfterClose(t *testing.T) {
	var tracker Tracker
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		a, b := net.Pipe()
		defer b.Close()
		wg.Add(1)
		go func() { defer wg.Done(); tracker.Add(a) }()
	}
	tracker.Close()
	wg.Wait()
	a, b := net.Pipe()
	defer b.Close()
	if tracker.Add(a) {
		t.Fatal("accepted after shutdown")
	}
	if _, e := b.Read(make([]byte, 1)); e != io.EOF {
		t.Fatal(e)
	}
}
