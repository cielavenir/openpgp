package encoding

import (
	"bytes"
	"io"
	"testing"
)

var mpiTests = []struct {
	encoded   []byte
	bytes     []byte
	bitLength uint16
	err       error
}{
	{
		encoded:   []byte{0x0, 0x1, 0x1},
		bytes:     []byte{0x1},
		bitLength: 1,
	},
	{
		encoded:   []byte{0x0, 0x9, 0x1, 0xff},
		bytes:     []byte{0x1, 0xff},
		bitLength: 9,
	},
	{
		encoded:   append([]byte{0x1, 0x0}, make([]byte, 0x20)...),
		bytes:     make([]byte, 0x20),
		bitLength: 0x100,
	},
	// EOF error,
	{
		encoded: []byte{},
		err:     io.ErrUnexpectedEOF,
	},
	{
		encoded: []byte{0x1, 0x0, 0x0},
		err:     io.ErrUnexpectedEOF,
	},
}

func TestMPI(t *testing.T) {
	for i, test := range mpiTests {
		mpi := new(MPI)
		if _, err := mpi.ReadFrom(bytes.NewBuffer(test.encoded)); err != nil {
			if !sameError(err, test.err) {
				t.Errorf("#%d: ReadFrom error got:%q", i, err)
			}
			continue
		}
		if b := mpi.Bytes(); !bytes.Equal(b, test.bytes) {
			t.Errorf("#%d: bad creation got:%x want:%x", i, b, test.bytes)
		}
		var buf bytes.Buffer
		if _, err := mpi.WriteTo(&buf); err != nil {
			t.Errorf("#%d: WriteTo error: %s", i, err)
		}
		if b := buf.Bytes(); !bytes.Equal(b, test.encoded) {
			t.Errorf("#%d: bad encoding got:%x want:%x", i, b, test.encoded)
		}
		if bl := mpi.BitLength(); bl != test.bitLength {
			t.Errorf("#%d: bad BitLength got:%d want:%d", i, bl, test.bitLength)
		}
	}
}
