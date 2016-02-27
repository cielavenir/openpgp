package algorithm

import (
	"crypto"
	"hash"
)

// Hash is an official hash function algorithm. See RFC 4880, section 9.4.
type Hash interface {
	// ID returns the algorithm Id, as a byte, of Hash.
	Id() uint8
	// Available reports whether the given hash function is linked into the binary.
	Available() bool
	// HashFunc simply returns the value of h so that Hash implements SignerOpts.
	HashFunc() crypto.Hash
	// New returns a new hash.Hash calculating the given hash function. New
	// panics if the hash function is not linked into the binary.
	New() hash.Hash
	// Size returns the length, in bytes, of a digest resulting from the given
	// hash function. It doesn't require that the hash function in question be
	// linked into the program.
	Size() int
}

var (
	MD5       = CryptoHash{1, crypto.MD5}
	SHA1      = CryptoHash{2, crypto.SHA1}
	RIPEMD160 = CryptoHash{3, crypto.RIPEMD160}
	SHA256    = CryptoHash{8, crypto.SHA256}
	SHA384    = CryptoHash{9, crypto.SHA384}
	SHA512    = CryptoHash{10, crypto.SHA512}
	SHA224    = CryptoHash{11, crypto.SHA224}
)

// HashById represents the different hash functions specified for OpenPGP. See
// http://www.iana.org/assignments/pgp-parameters/pgp-parameters.xhtml#pgp-parameters-14
var (
	HashById = map[uint8]Hash{
		MD5.Id():       MD5,
		SHA1.Id():      SHA1,
		RIPEMD160.Id(): RIPEMD160,
		SHA256.Id():    SHA256,
		SHA384.Id():    SHA384,
		SHA512.Id():    SHA512,
		SHA224.Id():    SHA224,
	}
)

// CryptoHash contains pairs relating OpenPGP's hash identifier with
// Go's crypto.Hash type. See RFC 4880, section 9.4.
type CryptoHash struct {
	id uint8
	crypto.Hash
}

// ID returns the algorithm Id, as a byte, of CryptoHash.
func (h CryptoHash) Id() uint8 {
	return h.id
}

func (h CryptoHash) String() string {
	switch h.id {
	case 1:
		return "MD5"
	case 2:
		return "SHA1"
	case 3:
		return "RIPEMD160"
	case 8:
		return "SHA256"
	case 9:
		return "SHA384"
	case 10:
		return "SHA512"
	case 11:
		return "SHA224"
	default:
		panic("unreachable")
	}
}
