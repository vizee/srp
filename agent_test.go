package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestAgentMissingTargetProcess(t *testing.T) {
	if os.Getenv("SRP_TEST_MISSING_TARGET") != "1" {
		return
	}
	agent := &AgentMode{key: bytes.Repeat([]byte{9}, 32), remote: os.Getenv("SRP_TEST_AGENT_REMOTE")}
	rc, bc, ok := agent.connectAndPair()
	if rc != nil {
		rc.Close()
	}
	if bc != nil {
		bc.Close()
	}
	if ok || bc != nil {
		t.Fatal("agent accepted a task without a target")
	}
}

func TestAgentReportsMissingTarget(t *testing.T) {
	listener := listenDataTestTCP(t)
	type result struct {
		ack map[string]any
		err error
	}
	reply := make(chan result, 1)
	session := base64.StdEncoding.EncodeToString(make([]byte, 16))
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			reply <- result{err: err}
			return
		}
		defer conn.Close()
		key, err := recvHello(conn, bytes.Repeat([]byte{9}, 32))
		if err == nil {
			err = sendObject(conn, key, map[string]any{
				"action": "dial", "seq": "1", "target": "",
				"transport": dataTransport, "session": session,
			}, time.Second)
		}
		var ack map[string]any
		if err == nil {
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			err = recvObject(conn, key, &ack)
		}
		reply <- result{ack, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAgentMissingTargetProcess$")
	command.Env = append(os.Environ(), "SRP_TEST_MISSING_TARGET=1", "SRP_TEST_AGENT_REMOTE="+listener.Addr().String())
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("agent helper: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "set -t on link or agent") {
		t.Errorf("missing target was not explained to the operator: %s", output)
	}
	got := <-reply
	if got.err != nil {
		t.Fatalf("missing target was not reported to link: %v", got.err)
	}
	message, _ := got.ack["error"].(string)
	if got.ack["success"] != false || got.ack["seq"] != "1" || got.ack["session"] != session || !strings.Contains(message, "set -t") {
		t.Fatalf("invalid failure acknowledgement: %v", got.ack)
	}
}
