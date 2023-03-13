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

func writeMessage(conn net.Conn, key []byte, payload []byte) error {
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

	_, err = conn.Write(buf)
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
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})
	return writeMessage(conn, key, buf)
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

func sendObject(conn net.Conn, key []byte, obj any) error {
	buf, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return writeMessage(conn, key, buf)
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

type LinkMode struct {
	key    []byte
	target string
	accept chan net.Conn
	seqs   uint64
}

func (l *LinkMode) link(rc net.Conn) (bool, net.Conn) {
	linkSeq := strconv.FormatUint(atomic.AddUint64(&l.seqs, 1), 10)

	tmpKey, err := recvHello(rc, l.key)
	if err != nil {
		dprintf("link[%s] recvHello: %v", linkSeq, err)
		return false, nil
	}

	dprintf("link[%s] received hello: tmpKey=%02x", linkSeq, tmpKey)

	// 握手完成后立即启动读协程，保持对连接状态的感知，等待 TCP 或者合法回复
	reply := make(chan bool, 1)
	go func() {
		var data map[string]any
		// 这里的读操作是为了感知 TCP 错误，不能设置超时
		err := recvObject(rc, tmpKey, &data)
		if err != nil {
			dprintf("link[%s] recvObject: %v", linkSeq, err)
			// 对端在建立连接后会设置 TCP keep-alive，如果连接中间出现故障会读到一个错误
			close(reply)
			return
		}
		seq, _ := data["seq"].(string)
		success, _ := data["success"].(bool)
		reply <- seq == linkSeq && success
	}()

	var uc net.Conn
	linked := false
	select {
	case uc = <-l.accept:
		uc.SetWriteDeadline(time.Now().Add(5 * time.Second))
		err := sendObject(rc, tmpKey, map[string]any{
			"action": "dial",
			"seq":    linkSeq,
			"target": l.target,
		})
		uc.SetWriteDeadline(time.Time{})
		if err != nil {
			dprintf("link[%s] sendObject: %v", linkSeq, err)
			break
		}

		select {
		case linked = <-reply:
		case <-time.After(time.Second * 10):
			// 在读协程中 recvJSON 不能设置超时，在这里感知 dial 超时
			dprintf("link[%s] dial timeout", linkSeq)
		}
	case linked = <-reply:
		dprintf("link[%s] accept cancel", linkSeq)
	}

	return linked, uc
}

func (l *LinkMode) handleRemote(rc net.Conn) {
	linked, uc := l.link(rc)
	if !linked {
		rc.Close()
		if uc != nil {
			uc.Close()
		}
		return
	}

	go pipe(rc, uc)
	pipe(uc, rc)
}

func (l *LinkMode) handleConn(conn net.Conn) {
	// 收到一个用户连接后尝试将它发给其他远程连接建立链接
	// TODO: 支持读到若干字节数据后再继续流程
	select {
	case l.accept <- conn:
	case <-time.After(time.Second * 30):
		conn.Close()
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func linkMain() {
	dprintf("srp link mode")
	var (
		listen string
		remote string
		target string
		key    string
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "srp link [option...]\n\n")
		flag.PrintDefaults()
	}
	flag.StringVar(&listen, "l", ":7770", "listen")
	flag.StringVar(&remote, "r", ":7771", "remote")
	flag.StringVar(&target, "t", "", "target")
	flag.StringVar(&key, "k", "", "key")
	flag.Parse()

	rawKey, err := loadKeyData(key)
	if err != nil {
		fatalf("invalid key: %v\n", err)
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fatalf("serve: %v\n", err)
	}
	rln, err := net.Listen("tcp", remote)
	if err != nil {
		fatalf("listen remote: %v\n", err)
	}

	link := &LinkMode{
		accept: make(chan net.Conn),
		target: target,
		key:    rawKey,
	}

	go func() {
		for {
			rconn, err := rln.Accept()
			if err != nil {
				dprintf("remote accept: %v", err)
				time.Sleep(time.Second)
				continue
			}
			go link.handleRemote(rconn)
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

	if tc, ok := rc.(*net.TCPConn); ok {
		tc.SetKeepAlivePeriod(time.Second * 30)
		tc.SetKeepAlive(true)
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
	})
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
	flag.DurationVar(&idleTimeout, "idle", 3*time.Hour, "idle timeout")
	flag.Parse()

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
	flag.Parse()

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

	args := os.Args
	if len(args) > 1 && args[1] == "-v" {
		debugLog = true
		args = args[1:]
	}
	if len(args) > 1 {
		cmd = args[1]
	}
	os.Args = args[1:]

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
