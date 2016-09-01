// Package blake2s implements the BLAKE2s hash algorithm.
//
// Written by Devi Mandiri <devi.mandiri@gmail.com>
package blake2s

import (
	"encoding/binary"
	"hash"
)

// The Blake2s blocksize in bytes.
const BlockSize  = 64

// The Blake2s maximum key size.
const KeySize = 32

var (
	// The Blake2s IV.
	iv = [8]uint32{
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
		0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
	}

	// Permutation of {0..15} used by the Blake2 functions.
	sigma = [10][16]uint8{
		{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
		{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
		{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
		{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
		{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
		{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
		{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
		{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
		{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
	}
)

type digest struct {
	h        [8]uint32
	t        [2]uint32
	f        [2]uint32
	buf      [2*BlockSize]byte
	buflen   int
	key      []byte
}

// New returns a new hash.Hash computing the Blake2s checksum.
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// NewKeyed returns a new hash.Hash computing the Blake2s checksum
// with the given key.
func NewKeyed(key []byte) hash.Hash {
	d := new(digest)
	d.key = key
	d.Reset()
	return d
}

func (d *digest) Reset() {
	keylen := len(d.key)
	if keylen > KeySize {
		keylen = KeySize
	}
	p := make([]byte, BlockSize)
	p[0] = 32
	p[1] = uint8(keylen)
	p[2] = 1
	p[3] = 1

	d.f[0] = 0
	d.f[1] = 0
	d.t[0] = 0
	d.t[1] = 0
	d.buflen = 0
	for i := 0; i < 8; i++ {
		d.h[i] = iv[i] ^ binary.LittleEndian.Uint32(p[i*4:])
	}
	if keylen > 0 {
		block := make([]byte, BlockSize)
		copy(block[:], d.key[:keylen])
		d.Write(block)
	}
}

func (*digest) BlockSize() int {
	return 64
}

func (d *digest) Size() int {
	return 32
}

// compress contains main algorithm of the Blake2s as defined in
// https://blake2.net/blake2_20130129.pdf
func (d *digest) compress() {
	var m, v [16]uint32
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint32(d.buf[i*4:])
	}
	for i := 0; i < 8; i++ {
		v[i] = d.h[i]
	}
	v[8] = iv[0]
	v[9] = iv[1]
	v[10] = iv[2]
	v[11] = iv[3]
	v[12] = d.t[0] ^ iv[4]
	v[13] = d.t[1] ^ iv[5]
	v[14] = d.f[0] ^ iv[6]
	v[15] = d.f[1] ^ iv[7]

	rotr32 := func (w uint32, c uint32) uint32 {
		return (w>>c) | (w<<(32-c))
	}
	G := func(r, i, a, b, c, d int) {
		v[a] = v[a] + v[b] + m[sigma[r][2*i+0]]
		v[d] = rotr32(v[d] ^ v[a], 16)
		v[c] = v[c] + v[d]
		v[b] = rotr32(v[b] ^ v[c], 12)
		v[a] = v[a] + v[b] + m[sigma[r][2*i+1]]
		v[d] = rotr32(v[d] ^ v[a], 8)
		v[c] = v[c] + v[d]
		v[b] = rotr32(v[b] ^ v[c], 7)
	}
	for i := 0; i < 10; i++ {
		G(i, 0, 0, 4,  8, 12);
		G(i, 1, 1, 5,  9, 13);
		G(i, 2, 2, 6, 10, 14);
		G(i, 3, 3, 7, 11, 15);
		G(i, 4, 0, 5, 10, 15);
		G(i, 5, 1, 6, 11, 12);
		G(i, 6, 2, 7,  8, 13);
		G(i, 7, 3, 4,  9, 14);
	}
	for i := 0; i < 8; i++ {
		d.h[i] = d.h[i] ^ v[i] ^ v[i+8]
	}
}

func (d *digest) incrementCounter(inc uint32) {
	d.t[0] += inc
	if d.t[0] < inc {
		d.t[1]--
	}
}

func (d *digest) Write(buf []byte) (int, error) {
	inlen := len(buf)
	offset := 0
	for inlen > 0 {
		left := d.buflen
		fill := 2*BlockSize - left
		if inlen > fill {
			copy(d.buf[left:], buf[offset:fill])
			d.buflen += fill
			d.incrementCounter(BlockSize)
			d.compress()
			copy(d.buf[:BlockSize], d.buf[BlockSize:])
			d.buflen -= BlockSize
			offset += fill
			inlen -= fill
		} else {
			copy(d.buf[left:], buf[offset:])
			d.buflen += inlen
			offset += inlen
			inlen -= inlen
		}
	}
	return 0, nil;
}

// Sum returns the Blake2s checksum of the data.
func (d *digest) Sum(buf []byte) []byte {
	if d.buflen > BlockSize {
		d.incrementCounter(BlockSize)
		d.compress()
		d.buflen -= BlockSize
		copy(d.buf[:d.buflen], d.buf[BlockSize:])
	}
	d.incrementCounter(uint32(d.buflen))
	d.f[0] = 0xffffffff;
	j := 2*BlockSize - d.buflen
	for i := 0; i < j; i++ {
		d.buf[i+d.buflen] = 0
	}
	d.compress()
	buffer := make([]byte, 32)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(buffer[i*4:], d.h[i])
	}
	return append(buf, buffer[:]...)
}
