// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/benburkert/openpgp/algorithm"
)

func bigFromBase10(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bigFromBase10 failed")
	}
	return b
}

var encryptedKeyPub = rsa.PublicKey{
	E: 65537,
	N: bigFromBase10("115804063926007623305902631768113868327816898845124614648849934718568541074358183759250136204762053879858102352159854352727097033322663029387610959884180306668628526686121021235757016368038585212410610742029286439607686208110250133174279811431933746643015923132833417396844716207301518956640020862630546868823"),
}

var encryptedKeyRSAPriv = &rsa.PrivateKey{
	PublicKey: encryptedKeyPub,
	D:         bigFromBase10("32355588668219869544751561565313228297765464314098552250409557267371233892496951383426602439009993875125222579159850054973310859166139474359774543943714622292329487391199285040721944491839695981199720170366763547754915493640685849961780092241140181198779299712578774460837139360803883139311171713302987058393"),
}

var encryptedKeyPriv = &PrivateKey{
	PublicKey: PublicKey{
		PubKeyAlgo: algorithm.RSA,
	},
	PrivateKey: encryptedKeyRSAPriv,
}

func TestDecryptingEncryptedKey(t *testing.T) {
	const encryptedKeyHex = "c18c032a67d68660df41c70104005789d0de26b6a50c985a02a13131ca829c413a35d0e6fa8d6842599252162808ac7439c72151c8c6183e76923fe3299301414d0c25a2f06a2257db3839e7df0ec964773f6e4c4ac7ff3b48c444237166dd46ba8ff443a5410dc670cb486672fdbe7c9dfafb75b4fea83af3a204fe2a7dfa86bd20122b4f3d2646cbeecb8f7be8"
	const expectedKeyHex = "d930363f7e0308c333b9618617ea728963d8df993665ae7be1092d4926fd864b"

	p, err := Read(readerFromHex(encryptedKeyHex))
	if err != nil {
		t.Errorf("error from Read: %s", err)
		return
	}
	ek, ok := p.(*EncryptedKey)
	if !ok {
		t.Errorf("didn't parse an EncryptedKey, got %#v", p)
		return
	}

	if ek.KeyId != 0x2a67d68660df41c7 || ek.Algo != algorithm.RSA {
		t.Errorf("unexpected EncryptedKey contents: %#v", ek)
		return
	}

	err = ek.Decrypt(encryptedKeyPriv, nil)
	if err != nil {
		t.Errorf("error from Decrypt: %s", err)
		return
	}

	if ek.Cipher.Id() != algorithm.AES256.Id() {
		t.Errorf("unexpected EncryptedKey contents: %#v", ek)
		return
	}

	keyHex := fmt.Sprintf("%x", ek.Key)
	if keyHex != expectedKeyHex {
		t.Errorf("bad key, got %s want %x", keyHex, expectedKeyHex)
	}
}

func TestEncryptingEncryptedKey(t *testing.T) {
	key := []byte{1, 2, 3, 4}
	const expectedKeyHex = "01020304"
	const keyId = 42

	pub := &PublicKey{
		PublicKey:  &encryptedKeyPub,
		KeyId:      keyId,
		PubKeyAlgo: algorithm.RSAEncryptOnly,
	}

	buf := new(bytes.Buffer)
	err := SerializeEncryptedKey(buf, pub, algorithm.AES128, key, nil)
	if err != nil {
		t.Errorf("error writing encrypted key packet: %s", err)
	}

	p, err := Read(buf)
	if err != nil {
		t.Errorf("error from Read: %s", err)
		return
	}
	ek, ok := p.(*EncryptedKey)
	if !ok {
		t.Errorf("didn't parse an EncryptedKey, got %#v", p)
		return
	}

	if ek.KeyId != keyId || ek.Algo != algorithm.RSAEncryptOnly {
		t.Errorf("unexpected EncryptedKey contents: %#v", ek)
		return
	}

	err = ek.Decrypt(encryptedKeyPriv, nil)
	if err != nil {
		t.Errorf("error from Decrypt: %s", err)
		return
	}

	if ek.Cipher.Id() != algorithm.AES128.Id() {
		t.Errorf("unexpected EncryptedKey contents: %#v", ek)
		return
	}

	keyHex := fmt.Sprintf("%x", ek.Key)
	if keyHex != expectedKeyHex {
		t.Errorf("bad key, got %s want %x", keyHex, expectedKeyHex)
	}
}

func TestSerializingEncryptedKey(t *testing.T) {
	const encryptedKeyHex = "c18c032a67d68660df41c70104005789d0de26b6a50c985a02a13131ca829c413a35d0e6fa8d6842599252162808ac7439c72151c8c6183e76923fe3299301414d0c25a2f06a2257db3839e7df0ec964773f6e4c4ac7ff3b48c444237166dd46ba8ff443a5410dc670cb486672fdbe7c9dfafb75b4fea83af3a204fe2a7dfa86bd20122b4f3d2646cbeecb8f7be8"

	p, err := Read(readerFromHex(encryptedKeyHex))
	if err != nil {
		t.Fatalf("error from Read: %s", err)
	}
	ek, ok := p.(*EncryptedKey)
	if !ok {
		t.Fatalf("didn't parse an EncryptedKey, got %#v", p)
	}

	var buf bytes.Buffer
	ek.Serialize(&buf)

	if bufHex := hex.EncodeToString(buf.Bytes()); bufHex != encryptedKeyHex {
		t.Fatalf("serialization of encrypted key differed from original. Original was %s, but reserialized as %s", encryptedKeyHex, bufHex)
	}
}

func TestDecryptingECDHEncryptedKey(t *testing.T) {
	p, err := Read(readerFromHex(ecdhEkDataHex))
	if err != nil {
		t.Fatal(err)
	}

	ek, ok := p.(*EncryptedKey)
	if !ok {
		t.Fatalf("didn't parse an EncryptedKey, got %#v", p)
	}

	if p, err = Read(readerFromHex(privKeyECDH256Hex)); err != nil {
		t.Fatalf("didn't parse a PrivateKey, got %#v", p)
	}

	pk, ok := p.(*PrivateKey)
	if !ok {
		t.Fatalf("didn't parse a PrivateKey, got %#v", p)
	}

	if err := pk.Decrypt([]byte("testing")); err != nil {
		t.Fatalf("failed to decrypt PrivateKey: %s", err)
	}

	if err := ek.Decrypt(pk, nil); err != nil {
		t.Fatalf("failed to decrypt EncryptedKey: %s", err)
	}
	if ek.Cipher.Id() != algorithm.AES256.Id() {
		t.Errorf("unexpected EncryptedKey contents: %#v", ek)
	}

	keyHex := fmt.Sprintf("%x", ek.Key)
	if keyHex != ecdhEkKeyHex {
		t.Errorf("bad key, got %s want %x", keyHex, ecdhEkKeyHex)
	}
}

const (
	ecdhEkKeyHex = "8267c6f6b1246af3cfcc278afabe3b55f520510fef0ff2cb5c3edd23e408a67f"

	ecdhEkDataHex = "847e03ba84fb25d0183e8512020304b5d92e9ed3eff76463c07193777fc1979be80c0591ad7a025ee0a96059bd40e734a2ee77bec755d7ed277a870c69b4aea17589f044db615a6d03b31b75e6301d305a0f06c42b09b88467eac410ce1cf6b424a9ceab2772e0788158fba3e7b9b6d084ca4ed1a6c9a66b99356a00291a67f9"
)
