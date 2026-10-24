package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSystemdServiceProcess(t *testing.T) {
	if os.Getenv("SRP_TEST_SYSTEMD_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			cmdArgs = os.Args[i+1:]
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing service arguments")
}

func TestSystemdServicePreservesArgumentBoundaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd executable paths require a Unix host")
	}
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(current)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	root := t.TempDir()
	directory := filepath.Join(root, "my $apps%dir")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "srp")
	target, err := os.OpenFile(binary, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(target, source)
	closeErr := target.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("copy executable: %v, %v", copyErr, closeErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestSystemdServiceProcess$", "--",
		"systemd-service", "agent", "-k", "@/etc/srp/private keys/$KEY%file.key", "-r", "localhost:7771")
	command.Env = append(os.Environ(), "SRP_TEST_SYSTEMD_PROCESS=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("service helper: %v\n%s", err, output)
	}
	want := `ExecStart="` + filepath.Join(root, "my $apps%%dir", "srp") + `" "agent" "-k" "@/etc/srp/private keys/$$KEY%%file.key" "-r" "localhost:7771"`
	if !strings.Contains(string(output), want+"\n") {
		t.Fatalf("generated unit did not preserve literal arguments; want %s\ngot:\n%s", want, output)
	}
}

func TestSystemdCommandLineEscapes(t *testing.T) {
	for _, tc := range []struct {
		arg  string
		want string
	}{
		{"", `""`},
		{"plain", `"plain"`},
		{"two words", `"two words"`},
		{`a"b\c`, `"a\"b\\c"`},
		{"$HOME/%n", `"$$HOME/%%n"`},
		{"line\n\t\r", `"line\n\t\r"`},
		{"中文目录", `"中文目录"`},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			got := systemdCommandLine("/usr/bin/srp", []string{tc.arg})
			if want := `"/usr/bin/srp" ` + tc.want; got != want {
				t.Fatalf("command line = %q; want %q", got, want)
			}
		})
	}
	if got := systemdCommandLine("/opt/my $apps%dir/srp", nil); got != `"/opt/my $apps%%dir/srp"` {
		t.Fatalf("executable escaping changed its literal dollar sign: %s", got)
	}
}
