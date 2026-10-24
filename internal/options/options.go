// Package options parses srp's command line. No configuration files are used.
package options

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Options struct {
	Mode, KeyPath, Remote, Listen string
	Services                      map[string]string
	Verbose                       bool
}

var serviceName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func Parse(args []string, home string) (Options, error) {
	var o Options
	if len(args) > 0 && args[0] == "-v" {
		o.Verbose = true
		args = args[1:]
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		return o, flag.ErrHelp
	}
	o.Mode = args[0]
	if o.Mode == "version" || o.Mode == "--version" {
		if len(args) != 1 {
			return o, errors.New("version takes no arguments")
		}
		o.Mode = "version"
		return o, nil
	}
	if o.Mode != "expose" && o.Mode != "relay" {
		return o, fmt.Errorf("unknown command %q", o.Mode)
	}
	fs := flag.NewFlagSet(o.Mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.KeyPath, "k", filepath.Join(home, ".config", "srp", "default.key"), "key file")
	var mappings string
	if o.Mode == "expose" {
		fs.StringVar(&o.Remote, "r", "127.0.0.1:7770", "relay address")
		fs.StringVar(&mappings, "t", "", "service=target mappings")
	} else {
		fs.StringVar(&o.Listen, "l", ":7770", "tunnel listen address")
		fs.StringVar(&mappings, "s", "", "service=listen mappings")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return o, err
	}
	if fs.NArg() != 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if o.KeyPath == "" {
		return o, errors.New("key file path is empty")
	}
	if o.Mode == "expose" {
		if err := address(o.Remote, false); err != nil {
			return o, fmt.Errorf("relay address: %w", err)
		}
	} else if err := address(o.Listen, true); err != nil {
		return o, fmt.Errorf("tunnel listen address: %w", err)
	}
	o.Services = make(map[string]string)
	for _, entry := range strings.Split(mappings, ",") {
		name, addr, ok := strings.Cut(strings.TrimSpace(entry), "=")
		name = strings.TrimSpace(name)
		addr = strings.TrimSpace(addr)
		if !ok || !serviceName.MatchString(name) {
			return o, fmt.Errorf("invalid service mapping %q", entry)
		}
		if _, ok := o.Services[name]; ok {
			return o, fmt.Errorf("duplicate service %q", name)
		}
		if err := address(addr, o.Mode == "relay"); err != nil {
			return o, fmt.Errorf("service %s: %w", name, err)
		}
		o.Services[name] = addr
	}
	if len(o.Services) > 256 {
		return o, errors.New("at most 256 services are allowed")
	}
	return o, nil
}

func address(s string, listen bool) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	if !listen && host == "" {
		return errors.New("target host is required")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("port must be a number from 1 to 65535")
	}
	return nil
}

func LoadKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %q: %w", path, err)
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("key file %q must contain 16, 24 or 32 raw bytes", path)
	}
	return key, nil
}

func Help(mode string) string {
	switch mode {
	case "expose":
		return "srp expose [-k key-file] [-r host:7770] -t service=host:port,...\n"
	case "relay":
		return "srp relay [-k key-file] [-l :7770] -s service=host:port,...\n"
	default:
		return "srp [-v] <expose|relay|version> [options]\n\n" + Help("expose") + Help("relay") + "\nDefault key: $HOME/.config/srp/default.key (16, 24 or 32 raw bytes)\n"
	}
}
