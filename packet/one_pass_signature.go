// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/binary"
	"io"
	"strconv"

	"github.com/benburkert/openpgp/algorithm"
	"github.com/benburkert/openpgp/errors"
)

// OnePassSignature represents a one-pass signature packet. See RFC 4880,
// section 5.4.
type OnePassSignature struct {
	SigType    SignatureType
	Hash       algorithm.Hash
	PubKeyAlgo algorithm.PublicKey
	KeyId      uint64
	IsLast     bool
}

const onePassSignatureVersion = 3

func (ops *OnePassSignature) parse(r io.Reader) (err error) {
	var buf [13]byte

	_, err = readFull(r, buf[:])
	if err != nil {
		return
	}
	if buf[0] != onePassSignatureVersion {
		err = errors.UnsupportedError("one-pass-signature packet version " + strconv.Itoa(int(buf[0])))
	}

	var ok bool
	ops.Hash, ok = algorithm.HashById[buf[2]]
	if !ok {
		return errors.UnsupportedError("hash function: " + strconv.Itoa(int(buf[2])))
	}

	ops.SigType = SignatureType(buf[1])

	if ops.PubKeyAlgo, ok = algorithm.PublicKeyById[buf[3]]; !ok {
		return errors.UnsupportedError("public key algorithm " + strconv.Itoa(int(buf[3])))
	}

	ops.KeyId = binary.BigEndian.Uint64(buf[4:12])
	ops.IsLast = buf[12] != 0
	return
}

// Serialize marshals the given OnePassSignature to w.
func (ops *OnePassSignature) Serialize(w io.Writer) error {
	var buf [13]byte
	buf[0] = onePassSignatureVersion
	buf[1] = uint8(ops.SigType)
	buf[2] = ops.Hash.Id()
	buf[3] = uint8(ops.PubKeyAlgo.Id())
	binary.BigEndian.PutUint64(buf[4:12], ops.KeyId)
	if ops.IsLast {
		buf[12] = 1
	}

	if err := serializeHeader(w, packetTypeOnePassSignature, len(buf)); err != nil {
		return err
	}
	_, err := w.Write(buf[:])
	return err
}
