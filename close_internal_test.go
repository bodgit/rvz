package rvz

import (
	"bytes"
	"io"
	"testing"

	"github.com/bodgit/rvz/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const closeTestMethod = 0xc105ed

type closeRecorder struct {
	io.Reader
	closed bool
}

func (c *closeRecorder) Close() error {
	c.closed = true

	return nil
}

//nolint:gochecknoglobals
var lastDecompressor *closeRecorder

//nolint:gochecknoinits
func init() {
	RegisterDecompressor(closeTestMethod, func(_ []byte, r io.Reader) (io.ReadCloser, error) {
		lastDecompressor = &closeRecorder{Reader: r}

		return lastDecompressor, nil
	})
}

func TestGroupReaderClosesOnError(t *testing.T) {
	t.Parallel()

	r := &reader{
		// Too short to hold the exception count
		ra: bytes.NewReader([]byte{0x00}),
		disc: disc{
			Compression: closeTestMethod,
			ChunkSize:   util.SectorSize,
		},
		group: []group{
			{
				Size: compressed | 1,
			},
		},
	}

	_, _, err := r.groupReader(0, 0, true)
	require.Error(t, err)

	if assert.NotNil(t, lastDecompressor) {
		assert.True(t, lastDecompressor.closed)
	}
}
