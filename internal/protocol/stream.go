package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

const recordSize = 32768
const recordLimit = uint64(1) << 32

// Stream deliberately embeds net.Conn rather than *net.TCPConn, hiding TCP
// copy shortcuts so neither io.Copy direction can bypass authenticated records.
type Stream struct {
	net.Conn
	readMu, writeMu     sync.Mutex
	readAEAD, writeAEAD cipher.AEAD
	readSeq, writeSeq   uint64
	buffered            []byte
	readErr, writeErr   error
	writeClosed         bool
}

func newStream(raw net.Conn, writeKey, readKey []byte) (*Stream, error) {
	wb, err := aes.NewCipher(writeKey)
	if err != nil {
		return nil, err
	}
	rb, err := aes.NewCipher(readKey)
	if err != nil {
		return nil, err
	}
	wa, err := cipher.NewGCM(wb)
	if err != nil {
		return nil, err
	}
	ra, err := cipher.NewGCM(rb)
	if err != nil {
		return nil, err
	}
	return &Stream{Conn: raw, writeAEAD: wa, readAEAD: ra}, nil
}
func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.readErr != nil {
		return 0, s.readErr
	}
	if len(s.buffered) == 0 {
		s.buffered, s.readErr = s.readRecord()
		if s.readErr != nil {
			return 0, s.readErr
		}
	}
	n := copy(p, s.buffered)
	s.buffered = s.buffered[n:]
	return n, nil
}
func (s *Stream) readRecord() ([]byte, error) {
	if s.readSeq >= recordLimit {
		return nil, errors.New("record limit exceeded")
	}
	var header [4]byte
	if _, err := io.ReadFull(s.Conn, header[:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n < 16 || n > recordSize+16 {
		return nil, errors.New("invalid encrypted record length")
	}
	payload := make([]byte, int(n))
	if _, err := io.ReadFull(s.Conn, payload); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], s.readSeq)
	plain, err := s.readAEAD.Open(payload[:0], nonce[:], payload, header[:])
	if err != nil {
		return nil, err
	}
	s.readSeq++
	if len(plain) == 0 {
		return nil, io.EOF
	}
	return plain, nil
}
func (s *Stream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	if s.writeClosed {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), recordSize)
		if err := s.writeRecord(p[:n]); err != nil {
			s.writeErr = err
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (s *Stream) writeRecord(p []byte) error {
	if s.writeSeq >= recordLimit {
		return errors.New("record limit exceeded")
	}
	frame := make([]byte, 4, 4+len(p)+16)
	binary.BigEndian.PutUint32(frame, uint32(len(p)+16))
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], s.writeSeq)
	frame = s.writeAEAD.Seal(frame, nonce[:], p, frame[:4])
	s.writeSeq++
	_, err := writeFull(s.Conn, frame)
	return err
}
func (s *Stream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	if s.writeClosed {
		return nil
	}
	if err := s.writeRecord(nil); err != nil {
		s.writeErr = err
		return err
	}
	s.writeClosed = true
	if c, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		s.writeErr = c.CloseWrite()
	}
	return s.writeErr
}
