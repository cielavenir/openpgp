package encoding

import "io"

// Field is an encoded field of an openpgp packet.
type Field interface {
	Bytes() []byte
	BitLength() uint16
	EncodedLength() uint16

	ReadFrom(r io.Reader) (int64, error)
	WriteTo(w io.Writer) (int64, error)
}
