package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCLIExamplesAndErrors(t *testing.T) {
	for _, tc := range []struct {
		args     []string
		status   int
		contains string
	}{
		{nil, 0, "expose"}, {[]string{"expose", "-h"}, 0, "-t"}, {[]string{"relay", "-h"}, 0, "-s"},
		{[]string{"version"}, 0, "2.0.0"}, {[]string{"agent"}, 2, "unknown command"},
		{[]string{"relay", "-s", "a=:0"}, 2, "port"},
		{[]string{"expose", "-k", "/nonexistent/srp/key", "-t", "ssh=127.0.0.1:22"}, 1, "key"},
	} {
		var out, errout bytes.Buffer
		got := run(context.Background(), tc.args, &out, &errout)
		if got != tc.status || !strings.Contains(out.String()+errout.String(), tc.contains) {
			t.Errorf("%v: status=%d out=%q err=%q", tc.args, got, out.String(), errout.String())
		}
	}
}

func TestCLICancellationInterruptsListenDNS(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	oldResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return nil, errors.New("test resolver released")
		}
	}}
	defer func() { net.DefaultResolver = oldResolver }()
	defer close(release)
	keyFile := filepath.Join(t.TempDir(), "key")
	if e := os.WriteFile(keyFile, bytes.Repeat([]byte{9}, 32), 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"relay", "-k", keyFile, "-l", "listen-test.invalid:7770", "-s", "ssh=:8022"}, io.Discard, io.Discard)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("DNS lookup did not start")
	}
	cancel()
	select {
	case status := <-done:
		if status != 0 {
			t.Errorf("requested cancellation returned exit status %d", status)
		}
	case <-time.After(time.Second):
		t.Error("CLI cancellation blocked in listen DNS resolution")
	}
}
