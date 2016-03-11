package algorithm

import "testing"

var dummyHash = CryptoHash{4, 4}

func TestHashName(t *testing.T) {
	s := SHA256.String()
	if s != "SHA256" {
		t.Fatalf("invalid string for SHA256 '%s'", s)
	}

	defer func() {
		if err := recover(); err == nil {
			t.Fatal("algorithm: unsupported hash should panic")
		}
	}()

	s = dummyHash.String()
	panic("dummyHash should panic")
}
