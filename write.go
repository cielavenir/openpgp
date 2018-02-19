// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"fmt"
	"hash"
	"io"
	"strconv"
	"time"

	"github.com/benburkert/openpgp/algorithm"
	"github.com/benburkert/openpgp/armor"
	"github.com/benburkert/openpgp/errors"
	"github.com/benburkert/openpgp/packet"
)

// DetachSign signs message with the private key from signer (which must
// already have been decrypted) and writes the signature to w.
// If config is nil, sensible defaults will be used.
func DetachSign(w io.Writer, signer *Entity, message io.Reader, config *packet.Config) error {
	return detachSign(w, signer, message, packet.SigTypeBinary, config)
}

// ArmoredDetachSign signs message with the private key from signer (which
// must already have been decrypted) and writes an armored signature to w.
// If config is nil, sensible defaults will be used.
func ArmoredDetachSign(w io.Writer, signer *Entity, message io.Reader, config *packet.Config) (err error) {
	return armoredDetachSign(w, signer, message, packet.SigTypeBinary, config)
}

// DetachSignText signs message (after canonicalising the line endings) with
// the private key from signer (which must already have been decrypted) and
// writes the signature to w.
// If config is nil, sensible defaults will be used.
func DetachSignText(w io.Writer, signer *Entity, message io.Reader, config *packet.Config) error {
	return detachSign(w, signer, message, packet.SigTypeText, config)
}

// ArmoredDetachSignText signs message (after canonicalising the line endings)
// with the private key from signer (which must already have been decrypted)
// and writes an armored signature to w.
// If config is nil, sensible defaults will be used.
func ArmoredDetachSignText(w io.Writer, signer *Entity, message io.Reader, config *packet.Config) error {
	return armoredDetachSign(w, signer, message, packet.SigTypeText, config)
}

func armoredDetachSign(w io.Writer, signer *Entity, message io.Reader, sigType packet.SignatureType, config *packet.Config) (err error) {
	out, err := armor.Encode(w, SignatureType, nil)
	if err != nil {
		return
	}
	err = detachSign(out, signer, message, sigType, config)
	if err != nil {
		return
	}
	return out.Close()
}

func detachSign(w io.Writer, signer *Entity, message io.Reader, sigType packet.SignatureType, config *packet.Config) (err error) {
	if signer.PrivateKey == nil {
		return errors.InvalidArgumentError("signing key doesn't have a private key")
	}
	if signer.PrivateKey.Encrypted {
		return errors.InvalidArgumentError("signing key is encrypted")
	}

	sig := new(packet.Signature)
	sig.SigType = sigType
	sig.PubKeyAlgo = signer.PrivateKey.PubKeyAlgo
	sig.Hash = config.Hash()
	sig.CreationTime = config.Now()
	sig.IssuerKeyId = &signer.PrivateKey.KeyId

	h, wrappedHash, err := hashForSignature(sig.Hash, sig.SigType)
	if err != nil {
		return
	}
	io.Copy(wrappedHash, message)

	err = sig.Sign(h, signer.PrivateKey, config)
	if err != nil {
		return
	}

	return sig.Serialize(w)
}

// FileHints contains metadata about encrypted files. This metadata is, itself,
// encrypted.
type FileHints struct {
	// IsBinary can be set to hint that the contents are binary data.
	IsBinary bool
	// FileName hints at the name of the file that should be written. It's
	// truncated to 255 bytes if longer. It may be empty to suggest that the
	// file should not be written to disk. It may be equal to "_CONSOLE" to
	// suggest the data should not be written to disk.
	FileName string
	// ModTime contains the modification time of the file, or the zero time if not applicable.
	ModTime time.Time
}

// SymmetricallyEncrypt acts like gpg -c: it encrypts a file with a passphrase.
// The resulting WriteCloser must be closed after the contents of the file have
// been written.
// If config is nil, sensible defaults will be used.
func SymmetricallyEncrypt(ciphertext io.Writer, passphrase []byte, hints *FileHints, config *packet.Config) (plaintext io.WriteCloser, err error) {
	if hints == nil {
		hints = &FileHints{}
	}

	key, err := packet.SerializeSymmetricKeyEncrypted(ciphertext, passphrase, config)
	if err != nil {
		return
	}
	w, err := packet.SerializeSymmetricallyEncrypted(ciphertext, config.Cipher(), key, config)
	if err != nil {
		return
	}

	literaldata := w
	if algo := config.Compression(); algo != packet.CompressionNone {
		var compConfig *packet.CompressionConfig
		if config != nil {
			compConfig = config.CompressionConfig
		}
		literaldata, err = packet.SerializeCompressed(w, algo, compConfig)
		if err != nil {
			return
		}
	}

	var epochSeconds uint32
	if !hints.ModTime.IsZero() {
		epochSeconds = uint32(hints.ModTime.Unix())
	}
	return packet.SerializeLiteral(literaldata, hints.IsBinary, hints.FileName, epochSeconds)
}

// intersectPreferences mutates and returns a prefix of a that contains only
// the values in the intersection of a and b. The order of a is preserved.
func intersectPreferences(a []uint8, b []uint8) (intersection []uint8) {
	var j int
	for _, v := range a {
		for _, v2 := range b {
			if v == v2 {
				a[j] = v
				j++
				break
			}
		}
	}

	return a[:j]
}

// Encrypt encrypts a message to a number of recipients and, optionally, signs
// it. hints contains optional information, that is also encrypted, that aids
// the recipients in processing the message. The resulting WriteCloser must
// be closed after the contents of the file have been written.
// If config is nil, sensible defaults will be used.
func Encrypt(ciphertext io.Writer, to []*Entity, hidden bool, signed *Entity, hints *FileHints, config *packet.Config) (plaintext io.WriteCloser, err error) {
	var signer *packet.PrivateKey
	if signed != nil {
		signKey, ok := signed.signingKey(config.Now())
		if !ok {
			return nil, errors.InvalidArgumentError("no valid signing keys")
		}
		signer = signKey.PrivateKey
		if signer == nil {
			return nil, errors.InvalidArgumentError("no private key in signing key")
		}
		if signer.Encrypted {
			return nil, errors.InvalidArgumentError("signing key must be decrypted")
		}
	}

	// These are the possible ciphers that we'll use for the message.
	candidateCiphers := algorithm.CipherSlice{
		algorithm.AES128,
		algorithm.AES256,
		algorithm.CAST5,
	}
	// These are the possible hash functions that we'll use for the signature.
	candidateHashes := algorithm.HashSlice{
		algorithm.SHA256,
		algorithm.SHA512,
		algorithm.SHA1,
		algorithm.RIPEMD160,
	}
	// In the event that a recipient doesn't specify any supported ciphers
	// or hash functions, these are the ones that we assume that every
	// implementation supports.
	defaultCiphers := candidateCiphers[len(candidateCiphers)-1:]
	defaultHashes := candidateHashes[len(candidateHashes)-1:]

	encryptKeys := make([]Key, len(to))
	for i := range to {
		var ok bool
		encryptKeys[i], ok = to[i].encryptionKey(config.Now())
		if !ok {
			return nil, errors.InvalidArgumentError("cannot encrypt a message to key id " + strconv.FormatUint(to[i].PrimaryKey.KeyId, 16) + " because it has no encryption keys")
		}

		sig := to[i].primaryIdentity().SelfSignature

		preferredSymmetric := sig.PreferredSymmetric
		if len(preferredSymmetric) == 0 {
			preferredSymmetric = defaultCiphers
		}
		preferredHashes := sig.PreferredHash
		if len(preferredHashes) == 0 {
			preferredHashes = defaultHashes
		}
		candidateCiphers = candidateCiphers.Intersect(preferredSymmetric)
		candidateHashes = candidateHashes.Intersect(preferredHashes)
	}

	if len(candidateCiphers) == 0 || len(candidateHashes) == 0 {
		return nil, errors.InvalidArgumentError("cannot encrypt because recipient set shares no common algorithms")
	}

	algo := candidateCiphers[0]
	// If the cipher specifed by config is a candidate, we'll use that.
	configuredCipher := config.Cipher()
	for _, c := range candidateCiphers {
		if c.Id() == configuredCipher.Id() {
			algo = c
			break
		}
	}

	var hash algorithm.Hash
	for _, h := range candidateHashes {
		if h.Available() {
			hash = h
			break
		}
	}

	// If the hash specified by config is a candidate, we'll use that.
	if configuredHash := config.Hash(); configuredHash.Available() {
		for _, h := range candidateHashes {
			if h == configuredHash {
				hash = h
				break
			}
		}
	}

	if hash == nil {
		hashId := candidateHashes[0].Id()
		name := "#" + strconv.Itoa(int(hashId))
		if hashAlgo, ok := algorithm.HashById[hashId].(fmt.Stringer); ok {
			name = hashAlgo.String()
		}
		return nil, errors.InvalidArgumentError("cannot encrypt because no candidate hash functions are compiled in. (Wanted " + name + " in this case.)")
	}

	symKey := make([]byte, algo.KeySize())
	if _, err := io.ReadFull(config.Random(), symKey); err != nil {
		return nil, err
	}

	for _, key := range encryptKeys {
		if err := packet.SerializeEncryptedKey(ciphertext, key.PublicKey, hidden, algo, symKey, config); err != nil {
			return nil, err
		}
	}

	encryptedData, err := packet.SerializeSymmetricallyEncrypted(ciphertext, algo, symKey, config)
	if err != nil {
		return
	}

	if signer != nil {
		ops := &packet.OnePassSignature{
			SigType:    packet.SigTypeBinary,
			Hash:       hash,
			PubKeyAlgo: signer.PubKeyAlgo,
			KeyId:      signer.KeyId,
			IsLast:     true,
		}
		if err := ops.Serialize(encryptedData); err != nil {
			return nil, err
		}
	}

	if hints == nil {
		hints = &FileHints{}
	}

	w := encryptedData
	if signer != nil {
		// If we need to write a signature packet after the literal
		// data then we need to stop literalData from closing
		// encryptedData.
		w = noOpCloser{encryptedData}

	}
	var epochSeconds uint32
	if !hints.ModTime.IsZero() {
		epochSeconds = uint32(hints.ModTime.Unix())
	}
	literalData, err := packet.SerializeLiteral(w, hints.IsBinary, hints.FileName, epochSeconds)
	if err != nil {
		return nil, err
	}

	if signer != nil {
		return signatureWriter{encryptedData, literalData, hash, hash.New(), signer, config}, nil
	}
	return literalData, nil
}

// signatureWriter hashes the contents of a message while passing it along to
// literalData. When closed, it closes literalData, writes a signature packet
// to encryptedData and then also closes encryptedData.
type signatureWriter struct {
	encryptedData io.WriteCloser
	literalData   io.WriteCloser
	hashType      algorithm.Hash
	h             hash.Hash
	signer        *packet.PrivateKey
	config        *packet.Config
}

func (s signatureWriter) Write(data []byte) (int, error) {
	s.h.Write(data)
	return s.literalData.Write(data)
}

func (s signatureWriter) Close() error {
	sig := &packet.Signature{
		SigType:      packet.SigTypeBinary,
		PubKeyAlgo:   s.signer.PubKeyAlgo,
		Hash:         s.hashType,
		CreationTime: s.config.Now(),
		IssuerKeyId:  &s.signer.KeyId,
	}

	if err := sig.Sign(s.h, s.signer, s.config); err != nil {
		return err
	}
	if err := s.literalData.Close(); err != nil {
		return err
	}
	if err := sig.Serialize(s.encryptedData); err != nil {
		return err
	}
	return s.encryptedData.Close()
}

// noOpCloser is like an ioutil.NopCloser, but for an io.Writer.
// TODO: we have two of these in OpenPGP packages alone. This probably needs
// to be promoted somewhere more common.
type noOpCloser struct {
	w io.Writer
}

func (c noOpCloser) Write(data []byte) (n int, err error) {
	return c.w.Write(data)
}

func (c noOpCloser) Close() error {
	return nil
}
