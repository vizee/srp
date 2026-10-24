package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func encryptedTestConn(t *testing.T, conn net.Conn, key []byte, linkSide bool) *encryptedConn {
	t.Helper()
	c, err := newEncryptedConn(conn, key, make([]byte, 16), linkSide)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEncryptedConnRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	for _, linkSide := range []bool{false, true} {
		for _, size := range []int{0, 1, 32767, 32768, 32769, 1024 * 1024} {
			t.Run(fmt.Sprintf("link=%t/size=%d", linkSide, size), func(t *testing.T) {
				wire := &messageTestConn{}
				writer := encryptedTestConn(t, wire, key, linkSide)
				payload := bytes.Repeat([]byte{'a'}, size)
				if n, err := writer.Write(payload); err != nil || n != len(payload) {
					t.Fatalf("Write = %d, %v", n, err)
				}
				if n, err := writer.Write(nil); n != 0 || err != nil {
					t.Fatalf("zero-length Write = %d, %v", n, err)
				}
				if n, err := writer.Write([]byte("tail")); n != 4 || err != nil {
					t.Fatalf("Write after empty Write = %d, %v", n, err)
				}
				if err := writer.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				wireLen := wire.Len()
				if err := writer.CloseWrite(); err != nil || wire.Len() != wireLen {
					t.Fatal("repeated CloseWrite must not append another EOF record")
				}
				if _, err := writer.Write([]byte("late")); err == nil {
					t.Fatal("Write succeeded after CloseWrite")
				}
				if size > 32 && bytes.Contains(wire.Bytes(), payload[:32]) {
					t.Fatal("plaintext appeared on the tunnel")
				}
				reader := encryptedTestConn(t, wire, key, !linkSide)
				var got bytes.Buffer
				buf := make([]byte, 7)
				for {
					n, err := reader.Read(buf)
					got.Write(buf[:n])
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				want := append(payload, []byte("tail")...)
				if !bytes.Equal(got.Bytes(), want) {
					t.Fatalf("received %d bytes; want %d", got.Len(), len(want))
				}
			})
		}
	}
}

func TestEncryptedConnRejectsInvalidRecords(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	wire := &messageTestConn{}
	writer := encryptedTestConn(t, wire, key, true)
	for _, payload := range []string{"first", "other"} {
		if _, err := writer.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(wire.Bytes())
	firstEnd := 4 + int(binary.LittleEndian.Uint32(original[:4]))
	secondEnd := firstEnd + 4 + int(binary.LittleEndian.Uint32(original[firstEnd:firstEnd+4]))
	corrupt := bytes.Clone(original)
	corrupt[4] ^= 1
	header := bytes.Clone(original)
	header[0]++
	oversized := make([]byte, 4)
	binary.LittleEndian.PutUint32(oversized, 1024*1024)
	tests := []struct {
		name     string
		wire     []byte
		key      []byte
		linkSide bool
	}{
		{"ciphertext changed", corrupt, key, false},
		{"header changed", header, key, false},
		{"wrong key", original, bytes.Repeat([]byte{8}, 16), false},
		{"reflected direction", original, key, true},
		{"empty stream", nil, key, false},
		{"partial header", original[:3], key, false},
		{"partial ciphertext", original[:firstEnd-1], key, false},
		{"missing EOF", original[:secondEnd], key, false},
		{"partial EOF", original[:len(original)-1], key, false},
		{"oversized frame", oversized, key, false},
		{"empty frame", make([]byte, 4), key, false},
		{"replayed frame", append(bytes.Clone(original[:firstEnd]), original...), key, false},
		{"reordered frames", append(append(bytes.Clone(original[firstEnd:secondEnd]), original[:firstEnd]...), original[secondEnd:]...), key, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &messageTestConn{}
			conn.Write(tc.wire)
			reader := encryptedTestConn(t, conn, tc.key, tc.linkSide)
			if _, err := io.ReadAll(reader); err == nil {
				t.Fatal("invalid or unauthenticated stream was accepted")
			}
			if n, err := reader.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatal("reader resumed after a failed record")
			}
		})
	}
}

type shortDataWriteConn struct {
	messageTestConn
	limit int
}

func (c *shortDataWriteConn) Write(p []byte) (int, error) {
	if len(p) > c.limit {
		p = p[:c.limit]
	}
	return c.messageTestConn.Write(p)
}

func TestEncryptedConnHandlesShortWrites(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	for _, limit := range []int{0, 3} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			conn := &shortDataWriteConn{limit: limit}
			writer := encryptedTestConn(t, conn, key, true)
			n, err := writer.Write([]byte("payload"))
			if limit == 0 {
				if n != 0 || !errors.Is(err, io.ErrShortWrite) {
					t.Fatalf("Write = %d, %v; want short write error", n, err)
				}
				if _, err := writer.Write([]byte("retry")); err == nil {
					t.Fatal("writer resumed after a failed record")
				}
				return
			}
			if err != nil || n != 7 {
				t.Fatalf("Write = %d, %v", n, err)
			}
			if err := writer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			reader := encryptedTestConn(t, conn, key, false)
			got, err := io.ReadAll(reader)
			if err != nil || string(got) != "payload" {
				t.Fatalf("ReadAll = %q, %v", got, err)
			}
		})
	}
}

func TestEncryptedConnHalfCloseWithoutTCP(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	deadline := time.Now().Add(5 * time.Second)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	key := bytes.Repeat([]byte{7}, 16)
	link := encryptedTestConn(t, a, key, true)
	agent := encryptedTestConn(t, b, key, false)
	done := make(chan error, 1)
	go func() {
		_, err := link.Write([]byte("request"))
		if err == nil {
			err = link.CloseWrite()
		}
		done <- err
	}()
	request, err := io.ReadAll(agent)
	if err != nil || string(request) != "request" {
		t.Fatalf("agent read = %q, %v", request, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := agent.Write([]byte("response"))
		if err == nil {
			err = agent.CloseWrite()
		}
		done <- err
	}()
	response, err := io.ReadAll(link)
	if err != nil || string(response) != "response" {
		t.Fatalf("link read = %q, %v", response, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type captureTunnelConn struct {
	net.Conn
	readWire  bytes.Buffer
	writeWire bytes.Buffer
}

func (c *captureTunnelConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.readWire.Write(p[:n])
	return n, err
}

func (c *captureTunnelConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.writeWire.Write(p[:n])
	return n, err
}

func (c *captureTunnelConn) CloseWrite() error {
	return c.Conn.(*net.TCPConn).CloseWrite()
}

func listenDataTestTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	listener.SetDeadline(time.Now().Add(5 * time.Second))
	return listener
}

func TestEncryptedProductionPairing(t *testing.T) {
	for _, preReadSize := range []int{0, 4} {
		t.Run(fmt.Sprintf("preRead=%d", preReadSize), func(t *testing.T) {
			agentListener := listenDataTestTCP(t)
			backendListener := listenDataTestTCP(t)
			client, linkUser := tcpTestPair(t)
			key := bytes.Repeat([]byte{9}, 32)
			link := &LinkMode{key: key, accept: make(chan *UserConn, 1)}
			link.accept <- &UserConn{conn: linkUser, preRead: []byte("head")[:preReadSize]}
			linkDone := make(chan *captureTunnelConn, 1)
			go func() {
				conn, err := agentListener.AcceptTCP()
				if err != nil {
					linkDone <- nil
					return
				}
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				capture := &captureTunnelConn{Conn: conn}
				link.handleAgent(capture)
				linkDone <- capture
			}()
			agent := &AgentMode{key: key, remote: agentListener.Addr().String(), target: backendListener.Addr().String()}
			rc, bc, ok := agent.connectAndPair()
			if rc != nil {
				t.Cleanup(func() { rc.Close() })
			}
			if bc != nil {
				t.Cleanup(func() { bc.Close() })
			}
			if !ok {
				t.Fatal("agent could not pair")
			}
			if _, ok := rc.(*encryptedConn); !ok {
				t.Fatal("agent pairing returned an unencrypted tunnel")
			}
			server, err := backendListener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { server.Close() })
			server.SetDeadline(time.Now().Add(5 * time.Second))
			agentDone := make(chan struct{})
			go func() { relay(rc, bc, nil); close(agentDone) }()
			request := bytes.Repeat([]byte("private-request-data"), 4096)
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(server)
			want := append([]byte("head")[:preReadSize:preReadSize], request...)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("backend received %d bytes, %v; want %d", len(got), err, len(want))
			}
			response := bytes.Repeat([]byte("private-response-data"), 4096)
			if _, err := server.Write(response); err != nil {
				t.Fatal(err)
			}
			if err := server.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err = io.ReadAll(client)
			if err != nil || !bytes.Equal(got, response) {
				t.Fatalf("client received %d bytes, %v; want %d", len(got), err, len(response))
			}
			select {
			case capture := <-linkDone:
				if capture == nil {
					t.Fatal("link accept failed")
				}
				for _, wire := range [][]byte{capture.readWire.Bytes(), capture.writeWire.Bytes()} {
					if bytes.Contains(wire, request[:32]) || bytes.Contains(wire, response[:32]) {
						t.Fatal("business plaintext appeared on the link-agent connection")
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("link relay did not terminate")
			}
			select {
			case <-agentDone:
			case <-time.After(5 * time.Second):
				t.Fatal("agent relay did not terminate")
			}
		})
	}
}

func TestLinkRejectsInvalidTransportAck(t *testing.T) {
	for _, transport := range []string{"", "unknown", "aes-gcm-v1"} {
		t.Run(transport, func(t *testing.T) {
			client, server := net.Pipe()
			user, upstream := net.Pipe()
			for _, conn := range []net.Conn{client, server, user, upstream} {
				conn := conn
				t.Cleanup(func() { conn.Close() })
				conn.SetDeadline(time.Now().Add(5 * time.Second))
			}
			key, tmpKey := make([]byte, 32), make([]byte, 16)
			link := &LinkMode{key: key, accept: make(chan *UserConn, 1)}
			link.accept <- &UserConn{conn: upstream}
			go link.handleAgent(server)
			if err := sendHello(client, key, tmpKey); err != nil {
				t.Fatal(err)
			}
			var request map[string]any
			if err := recvObject(client, tmpKey, &request); err != nil {
				t.Fatal(err)
			}
			if request["transport"] != "aes-gcm-v1" {
				t.Fatal("link did not request encrypted transport")
			}
			ack := map[string]any{"seq": request["seq"], "success": true, "session": request["session"]}
			if transport != "" {
				ack["transport"] = transport
			}
			if transport == "aes-gcm-v1" {
				ack["session"] = "wrong-session"
			}
			if err := sendObject(client, tmpKey, ack, time.Second); err != nil {
				t.Fatal(err)
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := client.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("link read = %v; want unsupported peer to be disconnected", err)
			}
		})
	}
}

func TestAgentRejectsInvalidTransportDial(t *testing.T) {
	for _, transport := range []string{"", "unknown", "aes-gcm-v1"} {
		t.Run(transport, func(t *testing.T) {
			linkListener := listenDataTestTCP(t)
			backendListener := listenDataTestTCP(t)
			key := bytes.Repeat([]byte{9}, 32)
			stop := make(chan struct{})
			defer close(stop)
			sent := make(chan error, 1)
			go func() {
				conn, err := linkListener.AcceptTCP()
				if err != nil {
					sent <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				tmpKey, err := recvHello(conn, key)
				if err != nil {
					sent <- err
					return
				}
				session := base64.StdEncoding.EncodeToString(make([]byte, 16))
				if transport == "aes-gcm-v1" {
					session = "invalid-session"
				}
				sent <- sendObject(conn, tmpKey, map[string]any{
					"action": "dial", "seq": "1", "target": backendListener.Addr().String(),
					"transport": transport, "session": session,
				}, time.Second)
				<-stop
			}()
			agent := &AgentMode{key: key, remote: linkListener.Addr().String()}
			rc, bc, ok := agent.connectAndPair()
			if rc != nil {
				rc.Close()
			}
			if bc != nil {
				bc.Close()
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			if ok || bc != nil {
				t.Fatal("agent accepted an incompatible dial or connected to its backend")
			}
		})
	}
}

func TestEncryptedConnRejectsNonceReuse(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	conn := &messageTestConn{}
	writer := encryptedTestConn(t, conn, key, true)
	writer.writeSeq = 1 << 32
	if _, err := writer.Write([]byte("payload")); err == nil || conn.Len() != 0 {
		t.Fatal("writer exceeded the per-key record limit")
	}
	if err := writer.CloseWrite(); err == nil {
		t.Fatal("CloseWrite resumed an exhausted stream")
	}
}

func TestEncryptedConnRejectsPreviousSession(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	wire := &messageTestConn{}
	writer := encryptedTestConn(t, wire, key, true)
	if _, err := writer.Write([]byte("previous session payload")); err != nil {
		t.Fatal(err)
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reader, err := newEncryptedConn(wire, key, bytes.Repeat([]byte{1}, 16), false)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(reader); err == nil || len(got) != 0 {
		t.Fatalf("previous-session replay returned %q, %v", got, err)
	}
}

func TestLinkRejectsUnsolicitedAck(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	client.SetDeadline(time.Now().Add(5 * time.Second))
	server.SetDeadline(time.Now().Add(5 * time.Second))
	key, tmpKey := make([]byte, 32), make([]byte, 16)
	link := &LinkMode{key: key, accept: make(chan *UserConn)}
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover(); server.Close() }()
		link.handleAgent(server)
	}()
	if err := sendHello(client, key, tmpKey); err != nil {
		t.Fatal(err)
	}
	if err := sendObject(client, tmpKey, map[string]any{"seq": "1", "success": true, "transport": "aes-gcm-v1"}, time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case recovered := <-done:
		if recovered != nil {
			t.Fatalf("unsolicited acknowledgement panicked: %v", recovered)
		}
	case <-time.After(time.Second):
		t.Fatal("unsolicited acknowledgement was not rejected")
	}
}
