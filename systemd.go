package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func systemdCommandLine(executable string, args []string) string {
	// Specifiers are expanded in both the executable path and arguments.
	words := []string{strconv.Quote(strings.ReplaceAll(executable, "%", "%%"))}
	for _, arg := range args {
		// Environment expansion applies to arguments, not the executable path.
		arg = strings.ReplaceAll(arg, "$", "$$")
		arg = strings.ReplaceAll(arg, "%", "%%")
		words = append(words, strconv.Quote(arg))
	}
	return strings.Join(words, " ")
}

func printSystemdService() {
	const serviceContent = `[Unit]
Description=Simple Reverse Proxy
After=%s

[Service]
ExecStart=%s
Restart=%s
RestartSec=%d
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
`

	var (
		after      string
		restart    string
		restartSec uint
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "srp systemd-service [option...] service-args...\n\n")
		flag.PrintDefaults()
	}
	flag.StringVar(&after, "after", "network-online.target", "Unit.After")
	flag.StringVar(&restart, "restart", "always", "Service.Restart")
	flag.UintVar(&restartSec, "restart-sec", 3, "Service.RestartSec")
	flag.CommandLine.Parse(cmdArgs)

	cmdline, err := os.Executable()
	if err == nil {
		cmdline, err = filepath.EvalSymlinks(cmdline)
	}
	if err != nil {
		fatalf("cannot get path of the program:%v", err)
	}

	fmt.Printf(serviceContent, after, systemdCommandLine(cmdline, flag.Args()), restart, restartSec)
}
