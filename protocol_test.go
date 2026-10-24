package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

// Control-message tests use in-memory connections and need no listening socket.
type messageTestConn struct {
	bytes.Buffer
}

func (*messageTestConn) Close() error                     { return nil }
func (*messageTestConn) LocalAddr() net.Addr              { return nil }
func (*messageTestConn) RemoteAddr() net.Addr             { return nil }
func (*messageTestConn) SetDeadline(time.Time) error      { return nil }
func (*messageTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*messageTestConn) SetWriteDeadline(time.Time) error { return nil }

func testCiphertext(t *testing.T, plain, key, iv []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(msg, plain)
	return msg
}

func TestDecryptRejectsMalformedInput(t *testing.T) {
	key, iv := bytes.Repeat([]byte{1}, 16), make([]byte, 16)
	badPadding := []struct {
		name  string
		plain []byte
	}{
		{"zero padding", append(bytes.Repeat([]byte{'a'}, 15), 0)},
		{"padding above block size", append(bytes.Repeat([]byte{'a'}, 15), 17)},
		{"padding above message size", append(bytes.Repeat([]byte{'a'}, 15), 255)},
		{"inconsistent padding", append(bytes.Repeat([]byte{'a'}, 14), 1, 2)},
	}
	tests := []struct {
		name string
		msg  []byte
		iv   []byte
	}{
		{"empty ciphertext", nil, iv},
		{"short ciphertext", []byte{1}, iv},
		{"unaligned ciphertext", make([]byte, 17), iv},
		{"empty IV", make([]byte, 16), nil},
		{"short IV", make([]byte, 16), make([]byte, 15)},
		{"long IV", make([]byte, 16), make([]byte, 17)},
	}
	for _, tc := range badPadding {
		tests = append(tests, struct {
			name string
			msg  []byte
			iv   []byte
		}{tc.name, testCiphertext(t, tc.plain, key, iv), iv})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("decrypt panicked instead of returning an error: %v", recovered)
				}
			}()
			if _, err := decrypt(tc.msg, key, tc.iv); err == nil {
				t.Error("decrypt accepted malformed input")
			}
		})
	}
}

func TestReadMessageRejectsMalformedFrames(t *testing.T) {
	for _, size := range []uint32{0, 1, 17, 1024*1024 + 16} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("readMessage panicked: %v", recovered)
				}
			}()
			conn := &messageTestConn{}
			var header [headerLen]byte
			binary.LittleEndian.PutUint32(header[:], size)
			conn.Write(header[:])
			if size < 1024 {
				conn.Write(make([]byte, size))
			}
			if _, err := readMessage(conn, make([]byte, 16)); err == nil {
				t.Error("readMessage accepted an invalid ciphertext length")
			}
		})
	}
	for _, frame := range [][]byte{make([]byte, headerLen-1), append([]byte{16, 0, 0, 0}, make([]byte, 17)...)} {
		conn := &messageTestConn{}
		conn.Write(frame)
		if _, err := readMessage(conn, make([]byte, 16)); err == nil {
			t.Error("readMessage accepted a truncated frame")
		}
	}
}

func TestRecvHelloRejectsMalformedPayloads(t *testing.T) {
	key := make([]byte, 32)
	for _, size := range []int{0, 1, helloLen - 1, helloLen, helloLen + sha1.Size - 1, helloLen + sha1.Size + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("recvHello panicked: %v", recovered)
				}
			}()
			conn := &messageTestConn{}
			if err := writeMessage(conn, key, make([]byte, size), 0); err != nil {
				t.Fatal(err)
			}
			if _, err := recvHello(conn, key); err == nil {
				t.Error("recvHello accepted an invalid payload length")
			}
		})
	}
	conn := &messageTestConn{}
	if err := writeMessage(conn, key, make([]byte, helloLen+sha1.Size), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := recvHello(conn, key); err == nil {
		t.Error("recvHello accepted an invalid signature")
	}
}

func TestMessageRoundTrip(t *testing.T) {
	for _, keySize := range []int{16, 24, 32} {
		for _, size := range []int{0, 1, 15, 16, 17, 4096} {
			t.Run(fmt.Sprintf("key=%d/payload=%d", keySize, size), func(t *testing.T) {
				key := bytes.Repeat([]byte{1}, keySize)
				payload := bytes.Repeat([]byte{'a'}, size)
				conn := &messageTestConn{}
				if err := writeMessage(conn, key, payload, 0); err != nil {
					t.Fatal(err)
				}
				got, err := readMessage(conn, key)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("readMessage = %x, %v; want original payload", got, err)
				}
			})
		}
	}
}

func TestHelloRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	tmpKey := bytes.Repeat([]byte{7}, tmpKeyLen)
	conn := &messageTestConn{}
	if err := sendHello(conn, key, tmpKey); err != nil {
		t.Fatal(err)
	}
	got, err := recvHello(conn, key)
	if err != nil || !bytes.Equal(got, tmpKey) {
		t.Fatalf("recvHello = %x, %v; want %x", got, err, tmpKey)
	}
}
