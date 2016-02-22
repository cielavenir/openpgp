package algorithm

import (
	"crypto/aes"
	"testing"
)

var dummyCipher = symmetricKey(0)

func TestKeySize(t *testing.T) {
	if AES128.KeySize() != 16 {
		t.Fatalf("algorithm: invalid AES-128 key size")
	}

	defer func() {
		if err := recover(); err == nil {
			t.Fatal("algorithm: unsupported cipher should panic")
		}
	}()

	_ = dummyCipher.KeySize()
	panic("dummyCipher should panic")
}

func TestBlockSize(t *testing.T) {
	if AES128.BlockSize() != aes.BlockSize {
		t.Fatalf("algorithm: invalid AES-128 block size")
	}

	defer func() {
		if err := recover(); err == nil {
			t.Fatal("algorithm: unsupported cipher should panic")
		}
	}()

	_ = dummyCipher.BlockSize()
	panic("dummyCipher should panic")
}

var (
	cipherListA = CipherSlice{AES128, AES256}
	cipherListB = CipherSlice{CAST5, AES256}
)

func TestCipherSlices(t *testing.T) {
	intersection := cipherListA.Intersect(cipherListB)
	if len(intersection) != 1 {
		t.Fatalf("expected a single cipher as the intersection of cipher lists A and B, but have %d ciphers",
			len(intersection))
	}

	idList := cipherListA.Ids()
	if idList[0] != AES256.Id() {
		t.Fatalf("expected intersection to be AES-256, but have %d",
			idList[0])
	}
}
