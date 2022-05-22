package lzma

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

const (
	unknownSize uint64 = 1<<64 - 1
)

// NewReader returns a new LZMA io.ReadCloser.
func NewReader(p []byte, reader io.Reader) (io.ReadCloser, error) {
	b := bytes.NewBuffer(p)
	_ = binary.Write(b, binary.LittleEndian, unknownSize)

	r, err := lzma.NewReader(io.MultiReader(b, reader))
	if err != nil {
		return nil, err
	}

	return io.NopCloser(r), nil
}
