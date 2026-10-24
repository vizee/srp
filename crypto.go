package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"os"
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
	if len(msg) == 0 || len(msg)%aes.BlockSize != 0 {
		return nil, errors.New("bad ciphertext length")
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("bad IV length")
	}
	cryptoCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(cryptoCipher, iv)
	plain := make([]byte, len(msg))
	cbc.CryptBlocks(plain, msg)
	padding := int(plain[len(plain)-1])
	if padding == 0 || padding > aes.BlockSize {
		return nil, errors.New("bad padding")
	}
	for _, b := range plain[len(plain)-padding:] {
		if int(b) != padding {
			return nil, errors.New("bad padding")
		}
	}
	return plain[:len(plain)-padding], nil
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
