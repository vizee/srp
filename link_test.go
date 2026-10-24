package main

import (
	"net"
	"testing"
	"time"
)

func TestHandleConnRejectsFailedPreRead(t *testing.T) {
	for _, payload := range []string{"", "x"} {
		t.Run(payload, func(t *testing.T) {
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			link := &LinkMode{preReadNum: 4, accept: make(chan *UserConn, 1)}
			done := make(chan struct{})
			go func() { link.handleConn(conn); close(done) }()
			if _, err := peer.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
			peer.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("failed pre-read did not return promptly")
			}
			select {
			case <-link.accept:
				t.Fatal("failed pre-read queued a closed client for pairing")
			default:
			}
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("failed pre-read left the client connection open")
			}
		})
	}
}
