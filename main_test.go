package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
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
