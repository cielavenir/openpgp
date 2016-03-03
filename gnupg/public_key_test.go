package gnupg

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/benburkert/openpgp/algorithm"
	"github.com/benburkert/openpgp/packet"
	"github.com/davecgh/go-spew/spew"
)

func TestSignature(t *testing.T) {
	config := &packet.Config{
		Rand: fixedRandom{},
	}

	p, err := packet.Read(readerFromHex(privKeyEdDSAHex))
	if err != nil {
		t.Fatalf("didn't parse a PrivateKey: %s", err)
	}
	privKey, ok := p.(*packet.PrivateKey)
	if !ok {
		t.Fatal("failed to parse PrivateKey: %#v", p)
	}
	if err := privKey.Decrypt([]byte("testing")); err != nil {
		t.Fatal("failed to decrypt: %s", err)
	}

	if p, err = packet.Read(readerFromHex(sigDataEdDSAHex)); err != nil {
		t.Fatalf("didn't parse a Signature: %s", err)
	}
	goodSig, ok := p.(*packet.Signature)
	if !ok {
		t.Fatal("failed to parse Signature: %#v", p)
	}

	h := goodSig.Hash.New()
	h.Reset()
	io.Copy(h, bytes.NewBufferString("testing"))
	if err := privKey.PublicKey.VerifySignature(h, goodSig); err != nil {
		t.Fatalf("failed to verify signature: %s", err)
	}

	sig := new(packet.Signature)
	sig.SigType = packet.SigTypeBinary
	sig.PubKeyAlgo = privKey.PubKeyAlgo
	sig.Hash = algorithm.SHA512
	sig.CreationTime = time.Unix(1456716505, 0)
	sig.IssuerKeyId = &privKey.KeyId

	h = sig.Hash.New()
	io.Copy(h, bytes.NewBufferString("testing"))
	if err = sig.Sign(h, privKey, config); err != nil {
		t.Fatalf("failed to sign: %s", err)
	}

	out := new(bytes.Buffer)
	if err = sig.Serialize(out); err != nil {
		t.Errorf("failed to serialize: %s", err)
	}

	expected, _ := hex.DecodeString(sigDataEdDSAHex)
	if !bytes.Equal(expected, out.Bytes()) {
		t.Errorf("output doesn't match input (got vs expected):\n%x\n%x", expected, out.Bytes())
	}

	if p, err = packet.Read(out); err != nil {
		t.Fatalf("didn't reparse a Signature: %s", err)
	}

	sig, ok = p.(*packet.Signature)
	if !ok {
		t.Fatal("failed to reparse Signature: %#v", p)
	}

	h.Reset()
	io.Copy(h, bytes.NewBufferString("testing"))
	if err := privKey.PublicKey.VerifySignature(h, sig); err != nil {
		t.Errorf("failed to reverify signature: %s", err)
	}

	fmt.Printf("good sig\n")
	spew.Dump(goodSig)

	fmt.Printf("bad sig\n")
	spew.Dump(sig)

}

const (
	privKeyEdDSAHex = "94860456d3813c16092b06010401da470f010107403087713a18bffc444f11cffb401e27c7795d0ed8e492d5e82177d92114453c12fe0703028dfd5c54bf092d54e61da0130859defcb427df0ecf6e92b696235c1b07e5f5293c77ae389e564c3bfdac0b01786c24d08f26d86e968661813f727fa737a124405327ce8b24185709ff441d3b2005dbb41d74657374696e67203c74657374696e674074657374696e672e636f6d3e8879041316080021050256d3813c021b03050b09080702061508090a0b020416020301021e01021780000a09101e4c5e835fac9ad3ee360100c4bd92b5e39b85a6180d273469e4e881b3bba04bbf11003c5e2795c11cdc851300fb07ee67145b6b7b5640446a0155503df52b2957342bc90e8b0897bab43b9a5209"

	sigDataEdDSAHex = "885e0400160a0006050256d3bad9000a09101e4c5e835fac9ad3efe001008d4cae2eb8cf7a9705f943eba50f2be60b5be0ac4560a5d3affc1ad06ae6147c01002e92411ec748272f8d675821e3cf41619fa733866f64f37c2b4d134bc5544406"
)

func readerFromHex(s string) io.Reader {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic("readerFromHex: bad input")
	}
	return bytes.NewBuffer(data)
}

type fixedRandom struct{}

func (fixedRandom) Read(p []byte) (n int, err error) {
	copy(p, make([]byte, len(p)))
	return len(p), nil
}

// hashed : efe04b3c8fb22b1dba4f30ac6586d8a4ddb2e7bd0ce0cf887e276848ee3deef3d16fdaa397497ea62e84c494fb28e998125b4bb15494cd1fdc224169a344ecd6
