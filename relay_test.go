package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func tcpTestPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	deadline := time.Now().Add(5 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestPipePreservesHalfClose(t *testing.T) {
	client, upstream := tcpTestPair(t)
	downstream, server := tcpTestPair(t)
	done := make(chan error, 2)
	go func() { done <- pipe(downstream, upstream) }()
	go func() { done <- pipe(upstream, downstream) }()

	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(server)
	if err != nil || string(request) != "request" {
		t.Fatalf("server read = %q, %v; want request followed by EOF", request, err)
	}
	response := bytes.Repeat([]byte("response"), 8192)
	if _, err := server.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("client received %d bytes, %v; want all %d response bytes", len(got), err, len(response))
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("pipe returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("pipe did not finish after both write sides closed")
		}
	}
}

func TestPipeCopyErrorClosesBothConnections(t *testing.T) {
	src, sourcePeer := net.Pipe()
	dst, destinationPeer := net.Pipe()
	for _, conn := range []net.Conn{src, sourcePeer, dst, destinationPeer} {
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	destinationPeer.Close()
	done := make(chan error, 1)
	go func() { done <- pipe(dst, src) }()
	if _, err := sourcePeer.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("pipe did not report the destination write failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pipe did not finish after a write failure")
	}
	sourcePeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := sourcePeer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("source peer read = %v; want EOF after relay failure", err)
	}
}

func TestRelayHalfCloseAcrossBothHops(t *testing.T) {
	for _, preReadSize := range []int{0, 4} {
		t.Run(fmt.Sprintf("preRead=%d", preReadSize), func(t *testing.T) {
			client, linkUser := tcpTestPair(t)
			linkAgent, agentRemote := tcpTestPair(t)
			agentBackend, server := tcpTestPair(t)
			preRead := make([]byte, preReadSize)
			if preReadSize > 0 {
				if _, err := client.Write([]byte("head")); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(linkUser, preRead); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan struct{}, 2)
			go func() { relay(linkAgent, linkUser, preRead); done <- struct{}{} }()
			go func() { relay(agentRemote, agentBackend, nil); done <- struct{}{} }()
			if _, err := client.Write([]byte("request")); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			want := "request"
			if preReadSize > 0 {
				want = "headrequest"
			}
			request, err := io.ReadAll(server)
			if err != nil || string(request) != want {
				t.Fatalf("server read = %q, %v; want %q", request, err, want)
			}
			response := bytes.Repeat([]byte("response"), 8192)
			if _, err := server.Write(response); err != nil {
				t.Fatal(err)
			}
			if err := server.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(client)
			if err != nil || !bytes.Equal(got, response) {
				t.Fatalf("client received %d bytes, %v; want %d bytes", len(got), err, len(response))
			}
			for i := 0; i < 2; i++ {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("relay did not finish after both directions reached EOF")
				}
			}
			for _, conn := range []*net.TCPConn{linkUser, linkAgent, agentRemote, agentBackend} {
				if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
					t.Errorf("completed relay connection read = %v; want closed connection", err)
				}
			}
		})
	}
}

func TestRelayPreReadFailureClosesBothConnections(t *testing.T) {
	src, sourcePeer := net.Pipe()
	dst, destinationPeer := net.Pipe()
	for _, conn := range []net.Conn{src, sourcePeer, dst, destinationPeer} {
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	destinationPeer.Close()
	done := make(chan struct{})
	go func() {
		relay(dst, src, []byte("head"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish after pre-read forwarding failed")
	}
	if _, err := sourcePeer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("source peer read = %v; want EOF after relay failure", err)
	}
}

func TestPipeWithoutHalfClose(t *testing.T) {
	src, sourcePeer := net.Pipe()
	dst, destinationPeer := net.Pipe()
	for _, conn := range []net.Conn{src, sourcePeer, dst, destinationPeer} {
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	done := make(chan error, 1)
	go func() { done <- pipe(dst, src) }()
	go func() {
		sourcePeer.Write([]byte("request"))
		sourcePeer.Close()
	}()
	got, err := io.ReadAll(destinationPeer)
	if err != nil || string(got) != "request" {
		t.Fatalf("destination read = %q, %v; want request followed by EOF", got, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pipe did not finish after EOF")
	}
}
