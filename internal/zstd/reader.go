package zstd

import (
	"io"
	"runtime"
	"sync"

	"github.com/klauspost/compress/zstd"
)

//nolint:gochecknoglobals
var zstdReaderPool sync.Pool

type readCloser struct {
	*zstd.Decoder
}

func (rc *readCloser) Close() error {
	zstdReaderPool.Put(rc)

	return nil
}

// NewReader returns a new Zstandard io.ReadCloser.
func NewReader(_ []byte, reader io.Reader) (io.ReadCloser, error) {
	var err error

	r, ok := zstdReaderPool.Get().(*zstd.Decoder)
	if ok {
		if err = r.Reset(reader); err != nil {
			return nil, err
		}
	} else {
		if r, err = zstd.NewReader(reader); err != nil {
			return nil, err
		}

		runtime.SetFinalizer(r, (*zstd.Decoder).Close)
	}

	return &readCloser{r}, nil
}
