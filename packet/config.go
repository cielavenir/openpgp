// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"crypto/rand"
	"io"
	"time"

	"github.com/benburkert/openpgp/algorithm"
)

// Config collects a number of parameters along with sensible defaults.
// A nil *Config is valid and results in all default values.
type Config struct {
	// Rand provides the source of entropy.
	// If nil, the crypto/rand Reader is used.
	Rand io.Reader
	// DefaultHash is the default hash function to be used.
	// If zero, SHA-256 is used.
	DefaultHash algorithm.Hash
	// DefaultCipher is the cipher to be used.
	// If zero, AES-128 is used.
	DefaultCipher algorithm.Cipher
	// Time returns the current time as the number of seconds since the
	// epoch. If Time is nil, time.Now is used.
	Time func() time.Time
	// DefaultCompressionAlgo is the compression algorithm to be
	// applied to the plaintext before encryption. If zero, no
	// compression is done.
	DefaultCompressionAlgo CompressionAlgo
	// CompressionConfig configures the compression settings.
	CompressionConfig *CompressionConfig
	// S2KCount is only used for symmetric encryption. It
	// determines the strength of the passphrase stretching when
	// the said passphrase is hashed to produce a key. S2KCount
	// should be between 1024 and 65011712, inclusive. If Config
	// is nil or S2KCount is 0, the value 65536 used. Not all
	// values in the above range can be represented. S2KCount will
	// be rounded up to the next representable value if it cannot
	// be encoded exactly. When set, it is strongly encrouraged to
	// use a value that is at least 65536. See RFC 4880 Section
	// 3.7.1.3.
	S2KCount int
	// RSABits is the number of bits in new RSA keys made with NewEntity.
	// If zero, then 2048 bit keys are created.
	RSABits int
}

func (c *Config) Random() io.Reader {
	if c == nil || c.Rand == nil {
		return rand.Reader
	}
	return c.Rand
}

func (c *Config) Hash() algorithm.Hash {
	if c == nil || c.DefaultHash == nil {
		return algorithm.SHA256
	}
	return c.DefaultHash
}

func (c *Config) Cipher() algorithm.Cipher {
	if c == nil {
		return algorithm.AES128
	}
	return c.DefaultCipher
}

func (c *Config) Now() time.Time {
	if c == nil || c.Time == nil {
		return time.Now()
	}
	return c.Time()
}

func (c *Config) Compression() CompressionAlgo {
	if c == nil {
		return CompressionNone
	}
	return c.DefaultCompressionAlgo
}

func (c *Config) PasswordHashIterations() int {
	if c == nil || c.S2KCount == 0 {
		return 0
	}
	return c.S2KCount
}
