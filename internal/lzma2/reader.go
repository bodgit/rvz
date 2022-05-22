package lzma2

import (
	"errors"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

// NewReader returns a new LZMA2 io.ReadCloser.
func NewReader(p []byte, reader io.Reader) (io.ReadCloser, error) {
	if len(p) != 1 {
		return nil, errors.New("lzma2: not enough properties")
	}

	config := lzma.Reader2Config{
		DictCap: (2 | (int(p[0]) & 1)) << (p[0]/2 + 11),
	}

	if err := config.Verify(); err != nil {
		return nil, err
	}

	r, err := config.NewReader2(reader)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(r), nil
}
