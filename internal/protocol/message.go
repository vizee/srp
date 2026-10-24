package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const MaxMessageSize = 65536

type Message struct {
	Type     string   `json:"type"`
	ID       string   `json:"id,omitempty"`
	Service  string   `json:"service,omitempty"`
	Code     string   `json:"code,omitempty"`
	Accepted []string `json:"accepted,omitempty"`
	Ignored  []string `json:"ignored,omitempty"`
}

func WriteMessage(w io.Writer, m Message) error {
	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(payload) > MaxMessageSize {
		return errors.New("control message is too large")
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	_, err = writeFull(w, frame)
	return err
}
func ReadMessage(r io.Reader) (Message, error) {
	var m Message
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return m, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > MaxMessageSize {
		return m, errors.New("invalid control message length")
	}
	payload := make([]byte, int(n))
	if _, err := io.ReadFull(r, payload); err != nil {
		return m, err
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		return m, err
	}
	if m.Type == "" {
		return m, errors.New("missing message type")
	}
	return m, nil
}
func writeFull(w io.Writer, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
		p = p[n:]
	}
	return total, nil
}
