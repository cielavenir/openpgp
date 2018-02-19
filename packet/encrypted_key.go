// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/binary"
	"io"
	"strconv"

	"github.com/benburkert/openpgp/algorithm"
	"github.com/benburkert/openpgp/encoding"
	"github.com/benburkert/openpgp/errors"
)

const encryptedKeyVersion = 3

// EncryptedKey represents a public-key encrypted session key. See RFC 4880,
// section 5.1.
type EncryptedKey struct {
	KeyId  uint64
	Algo   algorithm.PublicKey
	Cipher algorithm.Cipher // only valid after a successful Decrypt
	Key    []byte           // only valid after a successful Decrypt

	fields []encoding.Field
}

func (e *EncryptedKey) parse(r io.Reader) (err error) {
	var buf [10]byte
	_, err = readFull(r, buf[:])
	if err != nil {
		return
	}
	if buf[0] != encryptedKeyVersion {
		return errors.UnsupportedError("unknown EncryptedKey version " + strconv.Itoa(int(buf[0])))
	}
	e.KeyId = binary.BigEndian.Uint64(buf[1:9])

	var ok bool
	if e.Algo, ok = algorithm.PublicKeyById[buf[9]]; !ok {
		return errors.UnsupportedError("unknown PublicKey algorithm " + strconv.Itoa(int(buf[9])))
	}
	if e.fields, err = e.Algo.ParseEncryptedKey(r); err != nil {
		return err
	}

	_, err = consumeAll(r)
	return
}

func checksumKeyMaterial(key []byte) uint16 {
	var checksum uint16
	for _, v := range key {
		checksum += uint16(v)
	}
	return checksum
}

// Decrypt decrypts an encrypted session key with the given private key. The
// private key must have been decrypted first.
// If config is nil, sensible defaults will be used.
func (e *EncryptedKey) Decrypt(priv *PrivateKey, config *Config) error {
	// TODO(agl): use session key decryption routines here to avoid
	// padding oracle attacks.
	b, err := priv.PubKeyAlgo.Decrypt(config.Random(), priv.PrivateKey, e.fields, priv.Fingerprint)
	if err != nil {
		return err
	}

	var ok bool
	if e.Cipher, ok = algorithm.CipherById[b[0]]; !ok {
		return errors.UnsupportedError("unknown cipher: " + strconv.Itoa(int(b[0])))
	}

	e.Key = b[1: len(b)-2]
	expectedChecksum := uint16(b[len(b)-2])<<8 | uint16(b[len(b)-1])
	checksum := checksumKeyMaterial(e.Key)
	if checksum != expectedChecksum {
		return errors.StructuralError("EncryptedKey checksum incorrect")
	}

	return nil
}

// Serialize writes the encrypted key packet, e, to w.
func (e *EncryptedKey) Serialize(w io.Writer) error {
	serializeHeader(w, packetTypeEncryptedKey, 1/* version */ +8/* key id */ +1/* algo */ +encodedLength(e.fields))

	w.Write([]byte{encryptedKeyVersion})
	binary.Write(w, binary.BigEndian, e.KeyId)
	w.Write([]byte{byte(e.Algo.Id())})

	return writeFields(w, e.fields)
}

// SerializeEncryptedKey serializes an encrypted key packet to w that contains
// key, encrypted to pub.
// If config is nil, sensible defaults will be used.
func SerializeEncryptedKey(w io.Writer, pub *PublicKey, hidden bool, cipher algorithm.Cipher, key []byte, config *Config) error {
	var buf [10]byte
	buf[0] = encryptedKeyVersion
	if hidden {
		binary.BigEndian.PutUint64(buf[1:9], 0)
	} else {
		binary.BigEndian.PutUint64(buf[1:9], pub.KeyId)
	}
	buf[9] = byte(pub.PubKeyAlgo.Id())

	keyBlock := make([]byte, 1/* cipher type */ +len(key)+2 /* checksum */)
	keyBlock[0] = byte(cipher.Id())
	copy(keyBlock[1:], key)
	checksum := checksumKeyMaterial(key)
	keyBlock[1+len(key)] = byte(checksum >> 8)
	keyBlock[1+len(key)+1] = byte(checksum)

	keyFields, err := pub.PubKeyAlgo.Encrypt(config.Random(), pub.PublicKey, keyBlock, pub.Fingerprint)
	if err != nil {
		return err
	}

	packetLen := 10 /* header length */ + encodedLength(keyFields)
	if err = serializeHeader(w, packetTypeEncryptedKey, packetLen); err != nil {
		return err
	}
	if _, err = w.Write(buf[:]); err != nil {
		return err
	}
	return writeFields(w, keyFields)
}
