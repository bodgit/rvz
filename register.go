package rvz

import (
	"compress/bzip2"
	"errors"
	"io"
	"sync"

	"github.com/bodgit/rvz/internal/lzma"
	"github.com/bodgit/rvz/internal/lzma2"
	"github.com/bodgit/rvz/internal/zstd"
)

// Decompressor describes the function signature that decompression methods
// must implement to return a new instance of themselves. They are passed any
// property bytes and an io.Reader providing the stream of bytes.
type Decompressor func([]byte, io.Reader) (io.ReadCloser, error)

//nolint:gochecknoglobals
var decompressors sync.Map

//nolint:gochecknoinits
func init() {
	// None/Copy
	RegisterDecompressor(0, Decompressor(func(_ []byte, r io.Reader) (io.ReadCloser, error) {
		return io.NopCloser(r), nil
	}))
	// Purge. RVZ removed support for this algorithm from the original WIA format
	RegisterDecompressor(1, Decompressor(func(_ []byte, _ io.Reader) (io.ReadCloser, error) {
		return nil, errors.New("purge method not supported")
	}))
	// Bzip2
	RegisterDecompressor(2, Decompressor(func(_ []byte, r io.Reader) (io.ReadCloser, error) {
		return io.NopCloser(bzip2.NewReader(r)), nil
	}))
	// LZMA
	RegisterDecompressor(3, Decompressor(lzma.NewReader))
	// LZMA2
	RegisterDecompressor(4, Decompressor(lzma2.NewReader))
	// Zstandard
	RegisterDecompressor(5, Decompressor(zstd.NewReader))
}

// RegisterDecompressor allows custom decompressors for the specified method.
func RegisterDecompressor(method uint32, dcomp Decompressor) {
	if _, dup := decompressors.LoadOrStore(method, dcomp); dup {
		panic("decompressor already registered")
	}
}

func decompressor(method uint32) Decompressor {
	di, ok := decompressors.Load(method)
	if !ok {
		return nil
	}

	if d, ok := di.(Decompressor); ok {
		return d
	}

	return nil
}
