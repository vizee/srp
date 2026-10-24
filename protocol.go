package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

const (
	headerLen = 4 + msgBlockSize
	tmpKeyLen = 16
	helloLen  = tmpKeyLen + 56
)

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
	if payloadLen == 0 || payloadLen > maxPayloadLen || payloadLen%msgBlockSize != 0 {
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
	if len(payload) != helloLen+sha1.Size {
		return nil, errors.New("bad hello length")
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
