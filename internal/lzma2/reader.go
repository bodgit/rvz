// Package lzma2 provides an LZMA2 decompressor for RVZ groups.
package lzma2

import (
	"errors"
	"fmt"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

var errNotEnoughProperties = errors.New("lzma2: not enough properties")

// NewReader returns a new LZMA2 io.ReadCloser.
func NewReader(p []byte, reader io.Reader) (io.ReadCloser, error) {
	if len(p) != 1 {
		return nil, errNotEnoughProperties
	}

	config := lzma.Reader2Config{
		DictCap: (2 | (int(p[0]) & 1)) << (p[0]/2 + 11),
	}

	if err := config.Verify(); err != nil {
		return nil, fmt.Errorf("lzma2: %w", err)
	}

	r, err := config.NewReader2(reader)
	if err != nil {
		return nil, fmt.Errorf("lzma2: %w", err)
	}

	return io.NopCloser(r), nil
}
