package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

type UserConn struct {
	conn    net.Conn
	preRead []byte
}

type LinkMode struct {
	preReadNum uint
	key        []byte
	accept     chan *UserConn
	target     string
	seqs       uint64
}

func (l *LinkMode) link(ac net.Conn) (net.Conn, *UserConn) {
	linkSeq := strconv.FormatUint(atomic.AddUint64(&l.seqs, 1), 10)

	tmpKey, err := recvHello(ac, l.key)
	if err != nil {
		dprintf("link[%s] recvHello: %v", linkSeq, err)
		return nil, nil
	}
	var session [tmpKeyLen]byte
	if _, err := io.ReadFull(rand.Reader, session[:]); err != nil {
		dprintf("link[%s] generate data session: %v", linkSeq, err)
		return nil, nil
	}
	sessionID := base64.StdEncoding.EncodeToString(session[:])

	dprintf("link[%s] received hello", linkSeq)

	// 握手完成后立即启动读协程，保持对连接状态的感知，等待 TCP 或者合法回复
	agentAck := make(chan bool, 1)
	go func() {
		var data map[string]any
		// 这里的读操作是为了感知 TCP 错误，不能设置超时
		err := recvObject(ac, tmpKey, &data)
		if err != nil {
			dprintf("link[%s] recvObject: %v", linkSeq, err)
			// 对端在建立连接后会设置 TCP keep-alive，如果连接中间出现故障会读到一个错误
			close(agentAck)
			return
		}
		seq, _ := data["seq"].(string)
		success, _ := data["success"].(bool)
		transport, _ := data["transport"].(string)
		ackSession, _ := data["session"].(string)
		agentAck <- seq == linkSeq && success && transport == dataTransport && ackSession == sessionID
	}()

	var uc *UserConn
	acked := false
	select {
	case uc = <-l.accept:
		err := sendObject(ac, tmpKey, map[string]any{
			"action":    "dial",
			"seq":       linkSeq,
			"target":    l.target,
			"transport": dataTransport,
			"session":   sessionID,
		}, 5*time.Second)
		if err != nil {
			dprintf("link[%s] sendObject: %v", linkSeq, err)
			break
		}

		select {
		case acked = <-agentAck:
		case <-time.After(time.Second * 10):
			// 在读协程中 recvJSON 不能设置超时，在这里感知 dial 超时
			dprintf("link[%s] dial timeout", linkSeq)
		}
	case <-agentAck:
		dprintf("link[%s] accept cancel", linkSeq)
	}

	if !acked {
		return nil, uc
	}
	encrypted, err := newEncryptedConn(ac, tmpKey, session[:], true)
	if err != nil {
		dprintf("link[%s] encrypt agent connection: %v", linkSeq, err)
		return nil, uc
	}
	return encrypted, uc
}

func (l *LinkMode) handleAgent(ac net.Conn) {
	encrypted, uc := l.link(ac)
	if encrypted == nil {
		ac.Close()
		if uc != nil {
			uc.conn.Close()
		}
		return
	}

	relay(encrypted, uc.conn, uc.preRead)
}

func (l *LinkMode) handleConn(conn net.Conn) {
	// 收到一个用户连接后尝试将它发给其他远程连接建立链接
	// TODO: 支持读到若干字节数据后再继续流程
	var preRead []byte
	if l.preReadNum > 0 {
		preRead = make([]byte, l.preReadNum)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := io.ReadFull(conn, preRead)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			conn.Close()
			return
		}
	}
	select {
	case l.accept <- &UserConn{conn: conn, preRead: preRead}:
	case <-time.After(time.Second * 30):
		conn.Close()
	}
}

func linkMain() {
	dprintf("srp link mode")
	var (
		preReadNum uint
		listen     string
		agent      string
		target     string
		key        string
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "srp link [option...]\n\n")
		flag.PrintDefaults()
	}
	flag.UintVar(&preReadNum, "preRead", 0, "pre-read bytes")
	flag.StringVar(&listen, "l", ":7770", "listen")
	flag.StringVar(&agent, "a", ":7771", "agent")
	flag.StringVar(&target, "t", "", "target")
	flag.StringVar(&key, "k", "", "key")
	flag.CommandLine.Parse(cmdArgs)

	rawKey, err := loadKeyData(key)
	if err != nil {
		fatalf("invalid key: %v\n", err)
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fatalf("serve: %v\n", err)
	}
	aln, err := net.Listen("tcp", agent)
	if err != nil {
		fatalf("listen agent: %v\n", err)
	}

	link := &LinkMode{
		preReadNum: preReadNum,
		key:        rawKey,
		accept:     make(chan *UserConn),
		target:     target,
		seqs:       0,
	}

	go func() {
		for {
			ac, err := aln.Accept()
			if err != nil {
				dprintf("agent accept: %v", err)
				time.Sleep(time.Second)
				continue
			}
			go link.handleAgent(ac)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			dprintf("user accept: %v", err)
			time.Sleep(time.Second)
			continue
		}
		go link.handleConn(conn)
	}
}
