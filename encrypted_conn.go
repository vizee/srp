package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

const (
	dataTransport  = "aes-gcm-v1"
	dataRecordSize = 32 * 1024
	maxDataRecords = 1 << 32
)

// encryptedConn protects the link-agent data stream. Embedding the net.Conn
// interface deliberately hides TCP's ReadFrom/WriteTo, so io.Copy cannot bypass
// the encrypting Write and decrypting Read methods.
type encryptedConn struct {
	net.Conn
	readCipher  cipher.AEAD
	writeCipher cipher.AEAD
	readMu      sync.Mutex
	writeMu     sync.Mutex
	readSeq     uint64
	writeSeq    uint64
	readBuf     []byte
	readErr     error
	writeErr    error
	writeClosed bool
}

func newEncryptedConn(conn net.Conn, key []byte, session []byte, linkSide bool) (*encryptedConn, error) {
	if len(key) != tmpKeyLen || len(session) != tmpKeyLen {
		return nil, errors.New("bad data session key length")
	}
	derive := func(direction string) (cipher.AEAD, error) {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte("srp/" + dataTransport + "/" + direction))
		mac.Write(session)
		block, err := aes.NewCipher(mac.Sum(nil))
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	writeDirection, readDirection := "link-to-agent", "agent-to-link"
	if !linkSide {
		writeDirection, readDirection = readDirection, writeDirection
	}
	writeCipher, err := derive(writeDirection)
	if err != nil {
		return nil, err
	}
	readCipher, err := derive(readDirection)
	if err != nil {
		return nil, err
	}
	return &encryptedConn{Conn: conn, readCipher: readCipher, writeCipher: writeCipher}, nil
}

func (c *encryptedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if len(c.readBuf) == 0 {
		c.readBuf, c.readErr = c.readRecord()
		if c.readErr != nil {
			return 0, c.readErr
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *encryptedConn) readRecord() ([]byte, error) {
	if c.readSeq >= maxDataRecords {
		return nil, errors.New("data record limit exceeded")
	}
	var header [4]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	size := binary.LittleEndian.Uint32(header[:])
	if size < uint32(c.readCipher.Overhead()) || size > uint32(dataRecordSize+c.readCipher.Overhead()) {
		return nil, errors.New("bad data record length")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], c.readSeq)
	plain, err := c.readCipher.Open(payload[:0], nonce[:], payload, header[:])
	if err != nil {
		return nil, err
	}
	c.readSeq++
	if len(plain) == 0 {
		return nil, io.EOF
	}
	return plain, nil
}

func (c *encryptedConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.writeClosed {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(p) > 0 {
		size := len(p)
		if size > dataRecordSize {
			size = dataRecordSize
		}
		if err := c.writeRecord(p[:size]); err != nil {
			c.writeErr = err
			return written, err
		}
		written += size
		p = p[size:]
	}
	return written, nil
}

func (c *encryptedConn) writeRecord(payload []byte) error {
	if c.writeSeq >= maxDataRecords {
		return errors.New("data record limit exceeded")
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(payload)+c.writeCipher.Overhead()))
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], c.writeSeq)
	frame := make([]byte, 4, 4+len(payload)+c.writeCipher.Overhead())
	copy(frame, header[:])
	frame = append(frame, c.writeCipher.Seal(frame[4:4], nonce[:], payload, header[:])...)
	// Once encryption has used a nonce, a failed write must never reuse it.
	c.writeSeq++
	for len(frame) > 0 {
		n, err := c.Conn.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

// CloseWrite sends authenticated EOF before TCP FIN. The EOF record also
// supplies half-close semantics when the underlying connection has no FIN API.
func (c *encryptedConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	if c.writeClosed {
		return nil
	}
	if err := c.writeRecord(nil); err != nil {
		c.writeErr = err
		return err
	}
	c.writeClosed = true
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		c.writeErr = conn.CloseWrite()
	}
	return c.writeErr
}
