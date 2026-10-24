package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vizee/srp/internal/expose"
	"github.com/vizee/srp/internal/protocol"
	"github.com/vizee/srp/internal/relay"
)

func tcpListen(t *testing.T) net.Listener {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}
func reserveAddress(t *testing.T) string {
	t.Helper()
	ln := tcpListen(t)
	addr := ln.Addr().String()
	ln.Close()
	return addr
}
func sharedKeys(t *testing.T) *protocol.Keys {
	t.Helper()
	k, e := protocol.NewKeys(bytes.Repeat([]byte{9}, 32))
	if e != nil {
		t.Fatal(e)
	}
	return k
}

type networkRelay struct {
	address string
	cancel  context.CancelFunc
	done    chan error
}

func startRelay(t *testing.T, services map[string]string, ln net.Listener) *networkRelay {
	t.Helper()
	if ln == nil {
		ln = tcpListen(t)
	}
	r, e := relay.New(relay.Config{Keys: sharedKeys(t), Services: services})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &networkRelay{address: ln.Addr().String(), cancel: cancel, done: make(chan error, 1)}
	go func() { n.done <- r.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-n.done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("relay did not stop")
		}
	})
	return n
}

type readiness struct {
	once  sync.Once
	ready chan struct{}
}

func (r *readiness) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("services registered accepted=")) {
		r.once.Do(func() { close(r.ready) })
	}
	return len(p), nil
}
func startExpose(t *testing.T, remote string, targets map[string]string) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	signal := &readiness{ready: make(chan struct{})}
	logger := log.New(signal, "", 0)
	keys := sharedKeys(t)
	done := make(chan error, 1)
	go func() {
		done <- expose.Run(ctx, expose.Config{Keys: keys, Remote: remote, Targets: targets, Logger: logger})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("expose did not stop")
		}
	})
	select {
	case <-signal.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("expose did not register")
	}
	return cancel
}
func backend(t *testing.T, label string, banner bool) string {
	t.Helper()
	ln := tcpListen(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				if banner {
					c.Write([]byte("SSH-2.0-test\r\n"))
				}
				request, e := io.ReadAll(c)
				if e == nil {
					c.Write(append([]byte(label), request...))
				}
			}()
		}
	}()
	return ln.Addr().String()
}
func dialService(t *testing.T, addr string) *net.TCPConn {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for {
		raw, e := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if e == nil {
			c := raw.(*net.TCPConn)
			c.SetDeadline(time.Now().Add(5 * time.Second))
			t.Cleanup(func() { c.Close() })
			return c
		}
		if time.Now().After(end) {
			t.Fatal(e)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func exchange(t *testing.T, addr, request string) string {
	t.Helper()
	c := dialService(t, addr)
	if _, e := c.Write([]byte(request)); e != nil {
		t.Fatal(e)
	}
	if e := c.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	response, e := io.ReadAll(c)
	if e != nil {
		t.Fatal(e)
	}
	return string(response)
}
func manualControl(t *testing.T, remote string) *protocol.Stream {
	t.Helper()
	raw, e := net.Dial("tcp", remote)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Close() })
	s, e := protocol.ClientHandshake(context.Background(), raw, sharedKeys(t), protocol.Hello{Type: "control", Services: []string{"ssh"}})
	if e != nil {
		t.Fatal(e)
	}
	s.SetReadDeadline(time.Now().Add(3 * time.Second))
	m, e := protocol.ReadMessage(s)
	if e != nil || m.Type != "ready" {
		t.Fatalf("%+v %v", m, e)
	}
	return s
}
func manualData(t *testing.T, remote, id string) *protocol.Stream {
	t.Helper()
	raw, e := net.Dial("tcp", remote)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Close() })
	s, e := protocol.ClientHandshake(context.Background(), raw, sharedKeys(t), protocol.Hello{Type: "data", ID: id})
	if e != nil {
		t.Fatal(e)
	}
	s.SetDeadline(time.Now().Add(10 * time.Second))
	m, e := protocol.ReadMessage(s)
	if e != nil || m.Type != "ready" {
		t.Fatalf("%+v %v", m, e)
	}
	return s
}

func TestMultipleServicesAndExposes(t *testing.T) {
	ssh, web := reserveAddress(t), reserveAddress(t)
	r := startRelay(t, map[string]string{"ssh": ssh, "web": web}, nil)
	startExpose(t, r.address, map[string]string{"ssh": backend(t, "A:", false), "web": backend(t, "W:", false)})
	startExpose(t, r.address, map[string]string{"ssh": backend(t, "B:", false), "web": backend(t, "X:", false)})
	for name, addr := range map[string]string{"ssh": ssh, "web": web} {
		var results []string
		for i := 0; i < 8; i++ {
			results = append(results, exchange(t, addr, "request"))
		}
		expected := map[string]bool{"A:request": true, "B:request": true}
		if name == "web" {
			expected = map[string]bool{"W:request": true, "X:request": true}
		}
		for i := 2; i < len(results); i++ {
			if !expected[results[i]] || results[i] == results[i-1] {
				t.Fatalf("%s not round robin: %v", name, results)
			}
		}
	}
}
func TestClientCloseWriteBeforePairing(t *testing.T) {
	addr := reserveAddress(t)
	r := startRelay(t, map[string]string{"ssh": addr}, nil)
	control := manualControl(t, r.address)
	c := dialService(t, addr)
	c.Write([]byte("request sent before data handshake"))
	c.CloseWrite()
	m, e := protocol.ReadMessage(control)
	if e != nil {
		t.Fatal(e)
	}
	time.Sleep(30 * time.Millisecond)
	data := manualData(t, r.address, m.ID)
	request, e := io.ReadAll(data)
	if e != nil || string(request) != "request sent before data handshake" {
		t.Fatalf("%q %v", request, e)
	}
	response := bytes.Repeat([]byte("large response"), 32768)
	go func() { data.Write(response); data.CloseWrite() }()
	got, e := io.ReadAll(c)
	if e != nil || !bytes.Equal(got, response) {
		t.Fatalf("got %d: %v", len(got), e)
	}
}
func TestServerFirstBanner(t *testing.T) {
	addr := reserveAddress(t)
	r := startRelay(t, map[string]string{"ssh": addr}, nil)
	startExpose(t, r.address, map[string]string{"ssh": backend(t, "", true)})
	c := dialService(t, addr)
	banner := make([]byte, len("SSH-2.0-test\r\n"))
	if _, e := io.ReadFull(c, banner); e != nil || string(banner) != "SSH-2.0-test\r\n" {
		t.Fatalf("%q %v", banner, e)
	}
	c.CloseWrite()
	if _, e := io.ReadAll(c); e != nil {
		t.Fatal(e)
	}
}
func TestListenerRecoveryAfterPortReleased(t *testing.T) {
	occupied := tcpListen(t)
	addr := occupied.Addr().String()
	r := startRelay(t, map[string]string{"ssh": addr}, nil)
	startExpose(t, r.address, map[string]string{"ssh": backend(t, "ok:", false)})
	occupied.Close()
	if got := exchange(t, addr, "recover"); got != "ok:recover" {
		t.Fatal(got)
	}
}
func TestHeartbeatTimeoutClosesSessions(t *testing.T) {
	t.Parallel()
	addr := reserveAddress(t)
	r := startRelay(t, map[string]string{"ssh": addr}, nil)
	control := manualControl(t, r.address)
	c := dialService(t, addr)
	m, e := protocol.ReadMessage(control)
	if e != nil {
		t.Fatal(e)
	}
	data := manualData(t, r.address, m.ID)
	c.SetReadDeadline(time.Now().Add(9 * time.Second))
	if _, e := c.Read(make([]byte, 1)); e != io.EOF {
		t.Fatalf("silent control did not close source: %v", e)
	}
	data.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := data.Read(make([]byte, 1)); e == nil {
		t.Fatal("data retained after heartbeat timeout")
	}
}
func TestHeartbeatsKeepEstablishedIdleTunnelAlive(t *testing.T) {
	t.Parallel()
	addr := reserveAddress(t)
	r := startRelay(t, map[string]string{"ssh": addr}, nil)
	startExpose(t, r.address, map[string]string{"ssh": backend(t, "ok:", false)})
	c := dialService(t, addr)
	c.SetDeadline(time.Now().Add(16 * time.Second))
	c.Write([]byte("idle"))
	time.Sleep(11 * time.Second)
	c.CloseWrite()
	got, e := io.ReadAll(c)
	if e != nil || string(got) != "ok:idle" {
		t.Fatalf("idle tunnel: %q %v", got, e)
	}
}

type wireCapture struct {
	net.Conn
	owner *captureListener
}

func (c *wireCapture) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.owner.mu.Lock()
	c.owner.wire.Write(p[:n])
	c.owner.mu.Unlock()
	return n, e
}
func (c *wireCapture) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.owner.mu.Lock()
	c.owner.wire.Write(p[:n])
	c.owner.mu.Unlock()
	return n, e
}
func (c *wireCapture) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

type captureListener struct {
	net.Listener
	mu   sync.Mutex
	wire bytes.Buffer
}

func (l *captureListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return &wireCapture{Conn: c, owner: l}, nil
}
func TestTunnelHasNoBusinessPlaintext(t *testing.T) {
	addr := reserveAddress(t)
	ln := &captureListener{Listener: tcpListen(t)}
	r := startRelay(t, map[string]string{"ssh": addr}, ln)
	startExpose(t, r.address, map[string]string{"ssh": backend(t, "private-response:", false)})
	request := fmt.Sprintf("private-request-%s", bytes.Repeat([]byte("never-visible-on-tunnel"), 5000))
	if got := exchange(t, addr, request); got != "private-response:"+request {
		t.Fatal("bad response")
	}
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.wire.Len() < len(request) || bytes.Contains(ln.wire.Bytes(), []byte(request[:64])) || bytes.Contains(ln.wire.Bytes(), []byte("private-response:")) {
		t.Fatal("business data missing or plaintext on tunnel")
	}
}
func TestShutdownReleasesPorts(t *testing.T) {
	addr := reserveAddress(t)
	r := startRelay(t, map[string]string{"ssh": addr}, nil)
	cancelExpose := startExpose(t, r.address, map[string]string{"ssh": backend(t, "", false)})
	exchange(t, addr, "x")
	cancelExpose()
	// Wait for listener removal through the real control EOF path.
	end := time.Now().Add(2 * time.Second)
	for {
		ln, e := net.Listen("tcp", addr)
		if e == nil {
			ln.Close()
			break
		}
		if time.Now().After(end) {
			t.Fatal("service port not released")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
