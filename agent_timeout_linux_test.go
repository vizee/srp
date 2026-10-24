//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// A full loopback accept queue drops new SYNs without changing firewall rules.
func blockedAgentTestAddress(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	bound, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", bound.(*syscall.SockaddrInet4).Port)
	for i := 0; i < 16; i++ {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			return address
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
	}
	t.Skip("kernel did not apply backpressure to the full accept queue")
	return ""
}

func TestAgentDialTimeoutProcess(t *testing.T) {
	if os.Getenv("SRP_TEST_DIAL_PROCESS") != "1" {
		return
	}
	agent := &AgentMode{
		key: bytes.Repeat([]byte{9}, 32), remote: os.Getenv("SRP_TEST_DIAL_REMOTE"),
		target: os.Getenv("SRP_TEST_DIAL_TARGET"),
	}
	rc, bc, ok := agent.connectAndPair()
	if rc != nil {
		rc.Close()
	}
	if bc != nil {
		bc.Close()
	}
	if ok {
		t.Fatal("blocked dial unexpectedly paired")
	}
}

func TestAgentDialTimeout(t *testing.T) {
	for _, side := range []string{"link", "backend"} {
		side := side
		t.Run(side, func(t *testing.T) {
			t.Parallel()
			blocked := blockedAgentTestAddress(t)
			remote, target, limit := blocked, "", 12*time.Second
			var peerDone chan error
			if side == "backend" {
				listener := listenDataTestTCP(t)
				remote, target, limit = listener.Addr().String(), blocked, 7*time.Second
				peerDone = make(chan error, 1)
				go func() {
					conn, err := listener.AcceptTCP()
					if err != nil {
						peerDone <- err
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(15 * time.Second))
					key, err := recvHello(conn, bytes.Repeat([]byte{9}, 32))
					if err == nil {
						err = sendObject(conn, key, map[string]any{
							"action": "dial", "seq": "1", "target": target,
							"transport": dataTransport, "session": base64.StdEncoding.EncodeToString(make([]byte, 16)),
						}, time.Second)
					}
					if err == nil {
						_, err = io.Copy(io.Discard, conn)
					}
					peerDone <- err
				}()
			}
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAgentDialTimeoutProcess$", "-test.timeout=15s")
			command.Env = append(os.Environ(), "SRP_TEST_DIAL_PROCESS=1", "SRP_TEST_DIAL_REMOTE="+remote, "SRP_TEST_DIAL_TARGET="+target)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("%s dial did not return within %s", side, limit)
			}
			if err != nil {
				t.Fatalf("dial helper: %v\n%s", err, output)
			}
			if peerDone != nil {
				select {
				case err := <-peerDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("failed dial left the link connection open")
				}
			}
		})
	}
}
