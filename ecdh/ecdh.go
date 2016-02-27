package ecdh

import (
	"crypto/elliptic"
	"io"
	"math/big"

	"github.com/benburkert/openpgp/encoding"
)

func GenerateKey(c elliptic.Curve, rand io.Reader) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D, priv.PublicKey.X, priv.PublicKey.Y, err = elliptic.GenerateKey(c, rand)
	return
}

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int

	// TODO: shortcut to feed the KDF parameters into (algorithm.PublicKey).Encrypt/Decrypt
	KDF *encoding.BitString
}

type PrivateKey struct {
	PublicKey
	D []byte
}
