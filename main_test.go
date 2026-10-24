package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// Control-message tests use in-memory connections and need no listening socket.
type messageTestConn struct {
	bytes.Buffer
}

func (*messageTestConn) Close() error                     { return nil }
func (*messageTestConn) LocalAddr() net.Addr              { return nil }
func (*messageTestConn) RemoteAddr() net.Addr             { return nil }
func (*messageTestConn) SetDeadline(time.Time) error      { return nil }
func (*messageTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*messageTestConn) SetWriteDeadline(time.Time) error { return nil }

func testCiphertext(t *testing.T, plain, key, iv []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(msg, plain)
	return msg
}

func TestDecryptRejectsMalformedInput(t *testing.T) {
	key, iv := bytes.Repeat([]byte{1}, 16), make([]byte, 16)
	badPadding := []struct {
		name  string
		plain []byte
	}{
		{"zero padding", append(bytes.Repeat([]byte{'a'}, 15), 0)},
		{"padding above block size", append(bytes.Repeat([]byte{'a'}, 15), 17)},
		{"padding above message size", append(bytes.Repeat([]byte{'a'}, 15), 255)},
		{"inconsistent padding", append(bytes.Repeat([]byte{'a'}, 14), 1, 2)},
	}
	tests := []struct {
		name string
		msg  []byte
		iv   []byte
	}{
		{"empty ciphertext", nil, iv},
		{"short ciphertext", []byte{1}, iv},
		{"unaligned ciphertext", make([]byte, 17), iv},
		{"empty IV", make([]byte, 16), nil},
		{"short IV", make([]byte, 16), make([]byte, 15)},
		{"long IV", make([]byte, 16), make([]byte, 17)},
	}
	for _, tc := range badPadding {
		tests = append(tests, struct {
			name string
			msg  []byte
			iv   []byte
		}{tc.name, testCiphertext(t, tc.plain, key, iv), iv})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("decrypt panicked instead of returning an error: %v", recovered)
				}
			}()
			if _, err := decrypt(tc.msg, key, tc.iv); err == nil {
				t.Error("decrypt accepted malformed input")
			}
		})
	}
}

func TestReadMessageRejectsMalformedFrames(t *testing.T) {
	for _, size := range []uint32{0, 1, 17, 1024*1024 + 16} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("readMessage panicked: %v", recovered)
				}
			}()
			conn := &messageTestConn{}
			var header [headerLen]byte
			binary.LittleEndian.PutUint32(header[:], size)
			conn.Write(header[:])
			if size < 1024 {
				conn.Write(make([]byte, size))
			}
			if _, err := readMessage(conn, make([]byte, 16)); err == nil {
				t.Error("readMessage accepted an invalid ciphertext length")
			}
		})
	}
	for _, frame := range [][]byte{make([]byte, headerLen-1), append([]byte{16, 0, 0, 0}, make([]byte, 17)...)} {
		conn := &messageTestConn{}
		conn.Write(frame)
		if _, err := readMessage(conn, make([]byte, 16)); err == nil {
			t.Error("readMessage accepted a truncated frame")
		}
	}
}

func TestRecvHelloRejectsMalformedPayloads(t *testing.T) {
	key := make([]byte, 32)
	for _, size := range []int{0, 1, helloLen - 1, helloLen, helloLen + sha1.Size - 1, helloLen + sha1.Size + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("recvHello panicked: %v", recovered)
				}
			}()
			conn := &messageTestConn{}
			if err := writeMessage(conn, key, make([]byte, size), 0); err != nil {
				t.Fatal(err)
			}
			if _, err := recvHello(conn, key); err == nil {
				t.Error("recvHello accepted an invalid payload length")
			}
		})
	}
	conn := &messageTestConn{}
	if err := writeMessage(conn, key, make([]byte, helloLen+sha1.Size), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := recvHello(conn, key); err == nil {
		t.Error("recvHello accepted an invalid signature")
	}
}

func TestMessageRoundTrip(t *testing.T) {
	for _, keySize := range []int{16, 24, 32} {
		for _, size := range []int{0, 1, 15, 16, 17, 4096} {
			t.Run(fmt.Sprintf("key=%d/payload=%d", keySize, size), func(t *testing.T) {
				key := bytes.Repeat([]byte{1}, keySize)
				payload := bytes.Repeat([]byte{'a'}, size)
				conn := &messageTestConn{}
				if err := writeMessage(conn, key, payload, 0); err != nil {
					t.Fatal(err)
				}
				got, err := readMessage(conn, key)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("readMessage = %x, %v; want original payload", got, err)
				}
			})
		}
	}
}

func TestHelloRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	tmpKey := bytes.Repeat([]byte{7}, tmpKeyLen)
	conn := &messageTestConn{}
	if err := sendHello(conn, key, tmpKey); err != nil {
		t.Fatal(err)
	}
	got, err := recvHello(conn, key)
	if err != nil || !bytes.Equal(got, tmpKey) {
		t.Fatalf("recvHello = %x, %v; want %x", got, err, tmpKey)
	}
}

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
