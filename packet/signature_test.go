// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"github.com/benburkert/openpgp/algorithm"
)

var signatureTests = []struct {
	privateKeyHex string
	signatureHex  string
}{
	{
		privateKeyHex: privKeyRSAHex,
		signatureHex:  sigDataRSAHex,
	},
	{
		privateKeyHex: privKeyECDSA256Hex,
		signatureHex:  sigDataECDSA256Hex,
	},
	{
		privateKeyHex: privKeyECDSA384Hex,
		signatureHex:  sigDataECDSA384Hex,
	},
	{
		privateKeyHex: privKeyECDSA521Hex,
		signatureHex:  sigDataECDSA521Hex,
	},
}

func TestSignature(t *testing.T) {
	config := &Config{
		Rand: fixedRandom{},
	}

	for i, test := range signatureTests {
		packet, err := Read(readerFromHex(test.privateKeyHex))
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		privKey := packet.(*PrivateKey)
		if err := privKey.Decrypt([]byte("testing")); err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		sig := new(Signature)
		sig.SigType = SigTypeBinary
		sig.PubKeyAlgo = privKey.PubKeyAlgo
		sig.Hash = algorithm.SHA256
		sig.CreationTime = time.Unix(0x56cfdedf, 0)
		sig.IssuerKeyId = &privKey.KeyId

		h := sig.Hash.New()
		io.Copy(h, bytes.NewBufferString("testing"))
		if err = sig.Sign(h, privKey, config); err != nil {
			t.Errorf("#%d: failed to sign: %s", i, err)
			continue
		}

		h.Reset()
		io.Copy(h, bytes.NewBufferString("testing"))
		if err := privKey.PublicKey.VerifySignature(h, sig); err != nil {
			t.Errorf("#%d: failed to verify signature: %s", i, err)
			continue
		}

		out := new(bytes.Buffer)
		if err = sig.Serialize(out); err != nil {
			t.Errorf("#%d: failed to serialize: %s", i, err)
			continue
		}

		expected, _ := hex.DecodeString(test.signatureHex)
		if !bytes.Equal(expected, out.Bytes()) {
			t.Errorf("#%d: output doesn't match input (got vs expected):\n%s\n%s", i, hex.Dump(out.Bytes()), hex.Dump(expected))
		}

		packet, err = Read(out)
		if err != nil {
			t.Error(err)
			return
		}

		var ok bool
		sig, ok = packet.(*Signature)
		if !ok || sig.SigType != SigTypeBinary || sig.PubKeyAlgo != privKey.PubKeyAlgo || sig.Hash != algorithm.SHA256 {
			t.Errorf("#%d: failed to parse, got: %#v", i, packet)
		}
	}
}

const (
	sigDataRSAHex = "c29c040001080010050256cfdedf0910c181c053de849bf200002f41040062e776a45be669a08a967c8d8b639beaab5cb07a43f703e514b609df91b6cb7f7e4d53e3967600c1ad751dc543cf676bef1a921a73f8e67ed89630a56f067bced77f7c64e6e67d5c07ca9584ec8399e60be8d6dbfdc9039db10b8a8a484e8bd0b4491e0f8cdfbffaaa8a9719c975d6b14a6364e34e7e8032a92a282fede84416"

	sigDataECDSA256Hex = "c25e040013080010050256cfdedf0910db782fec74660d51000059ec00ff4d2cfaa1efb7ef89050889bfa087e4900b671cce810772588803a77589a136a200fe2966548fc824ec6cf6aec13b121c97e7c3937625dbcd9fe56da23c969db51ceb"
	sigDataECDSA384Hex = "c27e040013080010050256cfdedf0910fa393a3bef74364d00001b51017b07962b34b944f78098f6b63f50cb9834872a124ed57fd874b2b486c284605bed6db386a538bbf78bc48c6ab1560fa80c0180d2b70270c70248486e8ac53fad6fcb7a891ed99d78f8feeff6479a987ca8c300fa7e3779cb447d8616b91bd73cfc019c"
	sigDataECDSA521Hex = "c29f040013080010050256cfdedf09100d8ffe95c8da330600008cc902088d7fd8c5c86e7160bbe2cfdabbf097400cd34dfbfa2b164a31537e5e0010c19011e3ab7ac623c432ed811d7ee9ea2ef10480d9afd556df3611426a5fb6b0186fce02008760885f2d84517785eb6577ec8cf5e0d2d5e02f887bfded6d092c2359566ae6a6637c28d6db20b1acdc37319e6297804064d64f987d373e2573f6c2c97c9391"
)

type fixedRandom struct{}

func (fixedRandom) Read(p []byte) (n int, err error) {
	copy(p, make([]byte, len(p)))
	return len(p), nil
}
