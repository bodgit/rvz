// Package lzma provides an LZMA decompressor for RVZ groups.
package lzma

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
		return nil, fmt.Errorf("lzma: %w", err)
	}

	return io.NopCloser(r), nil
}
