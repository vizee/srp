package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const msgBlockSize = aes.BlockSize

func blockPadding(msg []byte) int {
	return aes.BlockSize - len(msg)%aes.BlockSize
}

func encrypt(buf []byte, plain []byte, key []byte, iv []byte) error {
	cryptoCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	padding := blockPadding(plain)
	msg := append(plain, bytes.Repeat([]byte{byte(padding)}, padding)...)
	cbc := cipher.NewCBCEncrypter(cryptoCipher, iv)
	cbc.CryptBlocks(buf, msg)
	return nil
}

func decrypt(msg []byte, key []byte, iv []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, nil
	}
	cryptoCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(cryptoCipher, iv)
	plain := make([]byte, len(msg))
	cbc.CryptBlocks(plain, msg)
	return plain[:len(plain)-int(plain[len(plain)-1])], nil
}

const (
	headerLen = 4 + msgBlockSize
	tmpKeyLen = 16
	helloLen  = tmpKeyLen + 56
)

var debugLog = false

func dprintf(foramt string, args ...any) {
	if debugLog {
		fmt.Printf(foramt+"\n", args...)
	}
}

func writeMessage(conn net.Conn, key []byte, payload []byte, timeout time.Duration) error {
	buf := make([]byte, headerLen+len(payload)+blockPadding(payload))
	var iv [msgBlockSize]byte
	_, err := io.ReadFull(rand.Reader, iv[:])
	if err != nil {
		return err
	}
	err = encrypt(buf[headerLen:], payload, key, iv[:])
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(buf)-headerLen))
	copy(buf[4:4+msgBlockSize], iv[:])
	if timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	}
	_, err = conn.Write(buf)
	if timeout > 0 {
		_ = conn.SetWriteDeadline(time.Time{})
	}
	return err
}

func readMessage(conn net.Conn, key []byte) ([]byte, error) {
	const maxPayloadLen = 1024 * 1024
	var header [headerLen]byte
	_, err := io.ReadFull(conn, header[:])
	if err != nil {
		return nil, err
	}

	payloadLen := binary.LittleEndian.Uint32(header[:])
	if payloadLen > maxPayloadLen {
		return nil, errors.New("bad payload length")
	}
	iv := header[4 : 4+msgBlockSize]
	payload := make([]byte, payloadLen)
	_, err = io.ReadFull(conn, payload)
	if err != nil {
		return nil, err
	}
	return decrypt(payload, key, iv)
}

func sendHello(conn net.Conn, key []byte, tmpKey []byte) error {
	buf := make([]byte, helloLen+sha1.Size)
	_, err := io.ReadFull(rand.Reader, buf[:helloLen-tmpKeyLen])
	if err != nil {
		return err
	}
	copy(buf[helloLen-tmpKeyLen:], tmpKey)
	sign := sha1.Sum(buf[:helloLen])
	copy(buf[helloLen:], sign[:])
	return writeMessage(conn, key, buf, 1*time.Second)
}

func recvHello(conn net.Conn, key []byte) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	payload, err := readMessage(conn, key)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	sign := sha1.Sum(payload[:helloLen])
	if !bytes.Equal(payload[helloLen:], sign[:]) {
		return nil, errors.New("bad sign")
	}
	return payload[helloLen-tmpKeyLen : helloLen], nil
}

func sendObject(conn net.Conn, key []byte, obj any, timeout time.Duration) error {
	buf, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return writeMessage(conn, key, buf, timeout)
}

func recvObject(conn net.Conn, key []byte, obj any) error {
	payload, err := readMessage(conn, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, obj)
}

// pipe 函数持续转发数据，在结束时关闭 dst 连接
func pipe(dst net.Conn, src net.Conn) error {
	_, err := io.Copy(dst, src)
	// 一般 pipe 成对出现，pipe 只负责关闭 dst
	dst.Close()
	if err == io.EOF {
		err = nil
	}
	return err
}

func loadKeyData(key string) ([]byte, error) {
	if key == "" {
		return nil, nil
	}
	if key[0] == '@' {
		return os.ReadFile(key[1:])
	}
	return base64.StdEncoding.DecodeString(key)
}

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

func (l *LinkMode) link(ac net.Conn) (bool, *UserConn) {
	linkSeq := strconv.FormatUint(atomic.AddUint64(&l.seqs, 1), 10)

	tmpKey, err := recvHello(ac, l.key)
	if err != nil {
		dprintf("link[%s] recvHello: %v", linkSeq, err)
		return false, nil
	}

	dprintf("link[%s] received hello: tmpKey=%02x", linkSeq, tmpKey)

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
		agentAck <- seq == linkSeq && success
	}()

	var uc *UserConn
	acked := false
	select {
	case uc = <-l.accept:
		err := sendObject(ac, tmpKey, map[string]any{
			"action": "dial",
			"seq":    linkSeq,
			"target": l.target,
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
	case acked = <-agentAck:
		dprintf("link[%s] accept cancel", linkSeq)
	}

	return acked, uc
}

func (l *LinkMode) handleAgent(ac net.Conn) {
	linked, uc := l.link(ac)
	if !linked {
		ac.Close()
		if uc != nil {
			uc.conn.Close()
		}
		return
	}

	go pipe(uc.conn, ac)

	if len(uc.preRead) > 0 {
		_, err := ac.Write(uc.preRead)
		if err != nil {
			dprintf("link established, send pre-read failed: %v", err)
			ac.Close()
			return
		}
	}
	pipe(ac, uc.conn)
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
		}
	}
	select {
	case l.accept <- &UserConn{conn: conn, preRead: preRead}:
	case <-time.After(time.Second * 30):
		conn.Close()
	}
}

var cmdArgs = os.Args[1:]

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
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

type AgentMode struct {
	key         []byte
	remote      string
	target      string
	idleTimeout time.Duration
}

func (a *AgentMode) connectAndPair() (rc net.Conn, bc net.Conn, ok bool) {
	var err error
	rc, err = net.Dial("tcp", a.remote)
	if err != nil {
		dprintf("net.Dial %s: %v", a.remote, err)
		return
	}

	if c, ok := rc.(*net.TCPConn); ok {
		c.SetKeepAlivePeriod(time.Second * 30)
		c.SetKeepAlive(true)
	}

	var tmpKey [tmpKeyLen]byte
	io.ReadFull(rand.Reader, tmpKey[:])

	err = sendHello(rc, a.key, tmpKey[:])
	if err != nil {
		dprintf("sendHello: %v", err)
		return
	}

	dprintf("sent hello: tmpKey=%02x", tmpKey[:])

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
	seq, _ := data["seq"].(string)
	target, _ := data["target"].(string)

	if a.target != "" {
		target = a.target
	}

	bc, err = net.Dial("tcp", target)
	if err != nil {
		dprintf("net.Dial %s: %v", target, err)
		return
	}

	err = sendObject(rc, tmpKey[:], map[string]any{
		"seq":     seq,
		"success": true,
	}, 0)
	if err != nil {
		dprintf("sendObject: %v", err)
		return
	}

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

	go pipe(rc, bc)
	pipe(bc, rc)
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
	flag.StringVar(&target, "t", "", "target")
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

	args := strings.Join(flag.Args(), " ")
	if args != "" {
		cmdline += " " + args
	}

	fmt.Printf(serviceContent, after, cmdline, restart, restartSec)
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
