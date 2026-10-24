package main

import (
	"flag"
	"fmt"
	"os"
)

var debugLog = false

func dprintf(foramt string, args ...any) {
	if debugLog {
		fmt.Printf(foramt+"\n", args...)
	}
}

var cmdArgs = os.Args[1:]

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func printHelp() {
	fmt.Fprintf(flag.CommandLine.Output(), `srp [-v] <command>

command:
    link              link mode
    agent             agent mode
    systemd-service   print systemd service unit

`)
}

func main() {
	var cmd string

	if len(cmdArgs) > 0 && cmdArgs[0] == "-v" {
		debugLog = true
		cmdArgs = cmdArgs[1:]
	}
	if len(cmdArgs) > 0 {
		cmd = cmdArgs[0]
		cmdArgs = cmdArgs[1:]
	}

	switch cmd {
	case "link":
		linkMain()
	case "agent":
		agentMain()
	case "systemd-service":
		printSystemdService()
	default:
		printHelp()
	}
}
