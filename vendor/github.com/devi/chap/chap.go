// Package chap implements Chacha20-Poly1305 AEAD.
package chap

import (
	"crypto/cipher"
	"errors"

	"github.com/devi/chap/internal/chacha20"
	"golang.org/x/crypto/poly1305"
)

const NonceSize = 12

var (
	ErrInvalidNonceSize      = errors.New("invalid nonce size")
	ErrInvalidMac            = errors.New("invalid authentication")
	ErrInvalidCiphertextSize = errors.New("invalid ciphertext size")
)

type chap struct {
	key *[32]byte
}

func (c *chap) NonceSize() int {
	return NonceSize
}

func (c *chap) Overhead() int {
	return poly1305.TagSize
}

func (c *chap) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != NonceSize {
		panic(ErrInvalidNonceSize)
	}

	var iv [16]byte
	copy(iv[4:], nonce[:])

	polykey := make([]byte, 64)
	chacha20.XORKeyStream(polykey, polykey, &iv, c.key)

	iv[0], iv[1], iv[2], iv[3] = 1, 0, 0, 0

	buf := make([]byte, len(plaintext))
	chacha20.XORKeyStream(buf, buf, &iv, c.key)

	ciphertext := make([]byte, len(plaintext))
	for i, v := range buf {
		ciphertext[i] = v ^ plaintext[i]
	}

	var subkey [32]byte
	copy(subkey[:], polykey[:32])

	var mac [16]byte
	poly1305.Sum(&mac, construct(data, ciphertext), &subkey)

	return append(dst, append(ciphertext, mac[:]...)...)
}

func (c *chap) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonceSize
	}
	if len(ciphertext) < c.Overhead() {
		return nil, ErrInvalidCiphertextSize
	}

	ciphertextCopy := ciphertext[:len(ciphertext)-c.Overhead()]
	macCopy := ciphertext[len(ciphertextCopy):]

	var iv [16]byte
	copy(iv[4:], nonce[:])

	polykey := make([]byte, 64)
	chacha20.XORKeyStream(polykey, polykey, &iv, c.key)

	var subkey [32]byte
	copy(subkey[:], polykey[:32])

	var mac [16]byte
	copy(mac[:], macCopy[:])

	if !poly1305.Verify(&mac, construct(data, ciphertextCopy), &subkey) {
		return nil, ErrInvalidMac
	}

	iv[0], iv[1], iv[2], iv[3] = 1, 0, 0, 0

	buf := make([]byte, len(ciphertextCopy))
	chacha20.XORKeyStream(buf, buf, &iv, c.key)

	plaintext := make([]byte, len(ciphertextCopy))
	for i, v := range buf {
		plaintext[i] = v ^ ciphertextCopy[i]
	}

	return plaintext, nil
}

// NewCipher creates and returns a new cipher.AEAD.
func NewCipher(key *[32]byte) cipher.AEAD {
	c := new(chap)
	c.key = key
	return c
}

// construct returns the constructed message for Poly1305 authentication.
func construct(data, ciphertext []byte) []byte {
	inlen, clen := len(data), len(ciphertext)
	pad0, pad1 := inlen%16, clen%16

	m := make([]byte, inlen)
	copy(m[:], data)
	if pad0 > 0 {
		m = append(m, make([]byte, 16-pad0)...)
	}
	m = append(m, ciphertext[:]...)
	if pad1 > 0 {
		m = append(m, make([]byte, 16-pad1)...)
	}

	var x [16]byte
	x[0] = byte(inlen)
	x[1] = byte(inlen >> 8)
	x[2] = byte(inlen >> 16)
	x[3] = byte(inlen >> 24)
	x[4] = byte(inlen >> 32)
	x[5] = byte(inlen >> 40)
	x[6] = byte(inlen >> 48)
	x[7] = byte(inlen >> 56)
	x[8] = byte(clen)
	x[9] = byte(clen >> 8)
	x[10] = byte(clen >> 16)
	x[11] = byte(clen >> 24)
	x[12] = byte(clen >> 32)
	x[13] = byte(clen >> 40)
	x[14] = byte(clen >> 48)
	x[15] = byte(clen >> 56)

	return append(m, x[:]...)
}
