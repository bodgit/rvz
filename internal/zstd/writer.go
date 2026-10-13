package zstd

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

const (
	// MinLevel is the lowest supported compression level.
	MinLevel = 1
	// MaxLevel is the highest supported compression level.
	MaxLevel = 22
)

// A Compressor compresses whole buffers, each as a separate Zstandard
// frame. It is safe for concurrent use.
type Compressor struct {
	enc *zstd.Encoder
}

// NewCompressor returns a new Compressor using the zstd compression level,
// which is mapped to the nearest level the encoder supports.
func NewCompressor(level int) (*Compressor, error) {
	// EncodeAll can only run as many times at once as there are
	// encoders, which defaults to GOMAXPROCS to match the writer
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)))
	if err != nil {
		return nil, fmt.Errorf("zstd: %w", err)
	}

	return &Compressor{enc: enc}, nil
}

// Compress appends src compressed to dst.
func (c *Compressor) Compress(dst, src []byte) []byte {
	return c.enc.EncodeAll(src, dst)
}

// Close releases the resources used by the Compressor.
func (c *Compressor) Close() error {
	if err := c.enc.Close(); err != nil {
		return fmt.Errorf("zstd: %w", err)
	}

	return nil
}
