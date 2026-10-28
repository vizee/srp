package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/vizee/srp/internal/expose"
	"github.com/vizee/srp/internal/options"
	"github.com/vizee/srp/internal/protocol"
	"github.com/vizee/srp/internal/relay"
)

const version = "2.0.0"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	home, homeErr := os.UserHomeDir()
	o, err := options.Parse(args, home)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, options.Help(o.Mode))
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "srp: %v\n", err)
		return 2
	}
	if o.Mode == "version" {
		fmt.Fprintf(stdout, "srp %s\n", version)
		return 0
	}
	if homeErr != nil && o.KeyPath == ".config/srp/default.key" {
		fmt.Fprintf(stderr, "srp: resolve home directory: %v\n", homeErr)
		return 1
	}
	psk, err := options.LoadKey(o.KeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "srp: %v\n", err)
		return 1
	}
	keys, err := protocol.NewKeys(psk)
	if err != nil {
		fmt.Fprintf(stderr, "srp: %v\n", err)
		return 1
	}
	logger := log.New(stderr, "srp: ", log.LstdFlags)
	if o.Mode == "expose" {
		err = expose.Run(ctx, expose.Config{Keys: keys, Remote: o.Remote, Targets: o.Services, Logger: logger, Verbose: o.Verbose})
	} else {
		var ln net.Listener
		ln, err = (&net.ListenConfig{}).Listen(ctx, "tcp", o.Listen)
		if err == nil {
			logger.Printf("relay tunnel listening on %s", ln.Addr())
			var r *relay.Relay
			r, err = relay.New(relay.Config{Keys: keys, Services: o.Services, Logger: logger, Verbose: o.Verbose, MaxPreflightConns: o.MaxPreflightConns})
			if err == nil {
				err = r.Serve(ctx, ln)
			} else {
				ln.Close()
			}
		}
	}
	if ctx.Err() != nil {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "srp: %v\n", err)
		return 1
	}
	return 0
}
