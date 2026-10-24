package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type AgentMode struct {
	key         []byte
	remote      string
	target      string
	idleTimeout time.Duration
}

func (a *AgentMode) connectAndPair() (rc net.Conn, bc net.Conn, ok bool) {
	var err error
	rc, err = net.DialTimeout("tcp", a.remote, 10*time.Second)
	if err != nil {
		dprintf("net.Dial %s: %v", a.remote, err)
		return
	}

	if c, ok := rc.(*net.TCPConn); ok {
		c.SetKeepAlivePeriod(time.Second * 30)
		c.SetKeepAlive(true)
	}

	var tmpKey [tmpKeyLen]byte
	if _, err = io.ReadFull(rand.Reader, tmpKey[:]); err != nil {
		dprintf("generate session key: %v", err)
		return
	}

	err = sendHello(rc, a.key, tmpKey[:])
	if err != nil {
		dprintf("sendHello: %v", err)
		return
	}

	dprintf("sent hello")

	if a.idleTimeout > 0 {
		rc.SetReadDeadline(time.Now().Add(a.idleTimeout))
	}
	var data map[string]any
	err = recvObject(rc, tmpKey[:], &data)
	if a.idleTimeout > 0 {
		rc.SetReadDeadline(time.Time{})
	}
	if err != nil {
		dprintf("recvObject: %v", err)
		return
	}

	action, _ := data["action"].(string)
	if action != "dial" {
		dprintf("bad action: %s", action)
		return
	}
	transport, _ := data["transport"].(string)
	if transport != dataTransport {
		dprintf("unsupported data transport: %s", transport)
		return
	}
	sessionID, _ := data["session"].(string)
	session, err := base64.StdEncoding.DecodeString(sessionID)
	if err != nil || len(session) != tmpKeyLen {
		dprintf("bad data session")
		return
	}
	seq, _ := data["seq"].(string)
	target, _ := data["target"].(string)

	if a.target != "" {
		target = a.target
	}
	if target == "" {
		const message = "target is required: set -t on link or agent"
		fmt.Fprintln(os.Stderr, message)
		if err := sendObject(rc, tmpKey[:], map[string]any{
			"seq": seq, "success": false, "error": message,
			"transport": dataTransport, "session": sessionID,
		}, time.Second); err != nil {
			dprintf("send dial failure: %v", err)
		}
		return
	}

	bc, err = net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		dprintf("net.Dial %s: %v", target, err)
		return
	}

	err = sendObject(rc, tmpKey[:], map[string]any{
		"seq":       seq,
		"success":   true,
		"transport": dataTransport,
		"session":   sessionID,
	}, 0)
	if err != nil {
		dprintf("sendObject: %v", err)
		return
	}

	encrypted, err := newEncryptedConn(rc, tmpKey[:], session, false)
	if err != nil {
		dprintf("encrypt remote connection: %v", err)
		return
	}
	rc = encrypted
	ok = true
	return
}

func (a *AgentMode) pairing() {
	rc, bc, ok := a.connectAndPair()

	if !ok {
		time.Sleep(time.Second)
	}
	go a.pairing()

	if !ok {
		if rc != nil {
			rc.Close()
		}
		if bc != nil {
			bc.Close()
		}
		return
	}

	relay(rc, bc, nil)
}

func agentMain() {
	dprintf("srp agent mode")
	var (
		remote      string
		target      string
		key         string
		idleTimeout time.Duration
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "srp agent [option...]\n\n")
		flag.PrintDefaults()
	}
	flag.StringVar(&remote, "r", "localhost:7771", "remote")
	flag.StringVar(&target, "t", "", "target address (required on either link or agent; overrides link target)")
	flag.StringVar(&key, "k", "", "key")
	flag.DurationVar(&idleTimeout, "idleTimeout", 3*time.Hour, "idle timeout")
	flag.CommandLine.Parse(cmdArgs)

	rawKey, err := loadKeyData(key)
	if err != nil {
		fatalf("invalid key: %v\n", err)
	}

	agent := &AgentMode{
		key:         rawKey,
		remote:      remote,
		target:      target,
		idleTimeout: idleTimeout,
	}

	go agent.pairing()

	select {}
}
