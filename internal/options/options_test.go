package options

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestMaxPreflightConns(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
	}{{"", 8}, {"1", 1}, {"256", 256}} {
		args := []string{"relay", "-s", "ssh=:22"}
		if tc.value != "" {
			args = append(args, "-max-preflight-conns", tc.value)
		}
		o, err := Parse(args, "/tmp")
		if err != nil || o.MaxPreflightConns != tc.want {
			t.Fatalf("%+v %v", o, err)
		}
	}
	for _, value := range []string{"0", "-1", "257", "bad"} {
		if _, err := Parse([]string{"relay", "-s", "ssh=:22", "-max-preflight-conns", value}, "/tmp"); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
}

func TestParseExamples(t *testing.T) {
	for _, tc := range []struct {
		args       []string
		mode, addr string
	}{
		{[]string{"expose", "-r", "100.100.100.100:7770", "-t", "ssh=127.0.0.1:22,myweb=192.168.1.11:8080,egress.baidu=www.baidu.com:443"}, "expose", "100.100.100.100:7770"},
		{[]string{"relay", "-l", ":7770", "-s", "ssh=:8022,myweb=100.100.100.100:18080,egress.baidu=127.0.0.1:443"}, "relay", ":7770"},
	} {
		o, err := Parse(tc.args, "/home/test")
		if err != nil {
			t.Fatal(err)
		}
		if o.Mode != tc.mode || len(o.Services) != 3 || (o.Remote != tc.addr && o.Listen != tc.addr) {
			t.Fatalf("bad options: %+v", o)
		}
		if o.KeyPath != "/home/test/.config/srp/default.key" {
			t.Fatal(o.KeyPath)
		}
	}
	o, err := Parse([]string{"-v", "expose", "-k", "/tmp/raw key", "-t", " SSH = [::1]:22 , ssh = localhost:23 "}, "/home/test")
	if err != nil || !o.Verbose || len(o.Services) != 2 || o.KeyPath != "/tmp/raw key" {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestParseRejectsInvalidMappings(t *testing.T) {
	for _, mapping := range []string{"", "ssh=:22", "a=localhost:0", "a=host:65536", "a=host:http", "a=host:22,", "a=host:22,a=host:23", "a", "a b=host:22", "=host:22"} {
		if _, err := Parse([]string{"expose", "-t", mapping}, "/tmp"); err == nil {
			t.Errorf("accepted %q", mapping)
		}
	}
	for _, args := range [][]string{{"agent"}, {"relay"}, {"expose", "-t", "a=host:22", "extra"}, {"relay", "-s", "a=:0"}} {
		if _, err := Parse(args, "/tmp"); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

func TestRawKeyFile(t *testing.T) {
	for _, n := range []int{0, 15, 16, 24, 32, 33} {
		p := filepath.Join(t.TempDir(), "key")
		want := bytes.Repeat([]byte{'\n'}, n)
		if err := os.WriteFile(p, want, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadKey(p)
		valid := n == 16 || n == 24 || n == 32
		if valid && (err != nil || !bytes.Equal(got, want)) {
			t.Fatalf("n=%d: %x %v", n, got, err)
		}
		if !valid && err == nil {
			t.Fatalf("accepted key length %d", n)
		}
	}
}
