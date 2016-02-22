package algorithm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"

	"golang.org/x/crypto/cast5"
)

// Cipher is an official symmetric key cipher algorithm. See RFC 4880,
// section 9.2.
type Cipher interface {
	// ID returns the algorithm Id, as a byte, of cipher.
	Id() uint8
	// KeySize returns the key size, in bytes, of cipher.
	KeySize() int
	// BlockSize returns the block size, in bytes, of cipher.
	BlockSize() int
	// New returns a fresh instance of the given cipher.
	New(key []byte) cipher.Block
}

const (
	TripleDES = symmetricKey(2)
	CAST5     = symmetricKey(3)
	AES128    = symmetricKey(7)
	AES192    = symmetricKey(8)
	AES256    = symmetricKey(9)
)

// CipherById represents the different block ciphers specified for OpenPGP. See
// http://www.iana.org/assignments/pgp-parameters/pgp-parameters.xhtml#pgp-parameters-13
var CipherById = map[uint8]Cipher{
	TripleDES.Id(): TripleDES,
	CAST5.Id():     CAST5,
	AES128.Id():    AES128,
	AES192.Id():    AES192,
	AES256.Id():    AES256,
}

type symmetricKey uint8

// ID returns the algorithm Id, as a byte, of cipher.
func (sk symmetricKey) Id() uint8 {
	return uint8(sk)
}

// KeySize returns the key size, in bytes, of cipher.
func (sk symmetricKey) KeySize() int {
	switch sk {
	case TripleDES:
		return 24
	case CAST5:
		return cast5.KeySize
	case AES128:
		return 16
	case AES192:
		return 24
	case AES256:
		return 32
	}
	return 0
}

// BlockSize returns the block size, in bytes, of cipher.
func (sk symmetricKey) BlockSize() int {
	switch sk {
	case TripleDES:
		return des.BlockSize
	case CAST5:
		return 8
	case AES128, AES192, AES256:
		return 16
	}
	return 0
}

// New returns a fresh instance of the given cipher.
func (sk symmetricKey) New(key []byte) (block cipher.Block) {
	switch sk {
	case TripleDES:
		block, _ = des.NewTripleDESCipher(key)
	case CAST5:
		block, _ = cast5.NewCipher(key)
	case AES128, AES192, AES256:
		block, _ = aes.NewCipher(key)
	}
	return
}

// CipherSlice is a slice of Ciphers.
type CipherSlice []Cipher

// Ids returns the id of each Cipher in cs.
func (cs CipherSlice) Ids() []uint8 {
	ids := make([]uint8, len(cs))
	for i, symmetricKey := range cs {
		ids[i] = symmetricKey.Id()
	}
	return ids
}

// Intersect mutates and returns a prefix of a that contains only the values in
// the intersection of a and b. The order of a is preserved.
func (a CipherSlice) Intersect(b CipherSlice) CipherSlice {
	var j int
	for _, v := range a {
		for _, v2 := range b {
			if v.Id() == v2.Id() {
				a[j] = v
				j++
				break
			}
		}
	}

	return a[:j]
}
