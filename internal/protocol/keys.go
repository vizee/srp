// Package protocol implements srp v2's authenticated wire protocol.
package protocol

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
)

type Keys struct{ root, enc, mac []byte }

func NewKeys(psk []byte) (*Keys, error) {
	if len(psk) != 16 && len(psk) != 24 && len(psk) != 32 {
		return nil, errors.New("key must contain 16, 24 or 32 bytes")
	}
	root, err := hkdf.Extract(sha256.New, psk, []byte("srp/v2"))
	if err != nil {
		return nil, err
	}
	enc, err := hkdf.Expand(sha256.New, root, "srp/v2/handshake/enc", 32)
	if err != nil {
		return nil, err
	}
	mac, err := hkdf.Expand(sha256.New, root, "srp/v2/handshake/mac", 32)
	if err != nil {
		return nil, err
	}
	return &Keys{root: root, enc: enc, mac: mac}, nil
}

func (k *Keys) session(raw []byte, nonce []byte) (toRelay, toExpose []byte, err error) {
	hash := sha256.New()
	hash.Write(raw)
	hash.Write(nonce)
	root, err := hkdf.Extract(sha256.New, k.root, hash.Sum(nil))
	if err != nil {
		return nil, nil, err
	}
	toRelay, err = hkdf.Expand(sha256.New, root, "srp/v2/expose-to-relay", 32)
	if err != nil {
		return nil, nil, err
	}
	toExpose, err = hkdf.Expand(sha256.New, root, "srp/v2/relay-to-expose", 32)
	return
}
