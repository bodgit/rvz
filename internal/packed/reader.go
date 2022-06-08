package packed

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/bodgit/plumbing"
	"github.com/bodgit/rvz/internal/padding"
)

const (
	padded   uint32 = 1 << 31
	sizeMask        = padded - 1
)

var pool sync.Pool //nolint:gochecknoglobals

type readCloser struct {
	rc     io.ReadCloser
	src    io.ReadCloser
	size   int64
	buf    *bytes.Buffer
	offset int64
}

func (rc *readCloser) nextReader() (err error) {
	var size uint32
	if err = binary.Read(rc.rc, binary.BigEndian, &size); err != nil {
		return err
	}

	rc.size = int64(size & sizeMask)

	if size&padded == padded {
		nrc, err := padding.NewReadCloser(rc.rc, rc.offset)
		if err != nil {
			return err
		}

		rc.src = plumbing.LimitReadCloser(nrc, rc.size)
	} else {
		// Intentionally "hide" the underlying Close method
		rc.src = io.NopCloser(io.LimitReader(rc.rc, rc.size))
	}

	return nil
}

func (rc *readCloser) read() (err error) {
	for {
		if rc.size == 0 {
			if err = rc.nextReader(); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}

				return
			}
		}

		var (
			n         int64
			remaining = int64(rc.buf.Cap() - rc.buf.Len())
		)

		if remaining >= rc.size {
			n, err = io.Copy(rc.buf, rc.src)
		} else {
			n, err = io.CopyN(rc.buf, rc.src, remaining)
		}

		if err != nil {
			return
		}

		rc.size -= n
		rc.offset += n

		if rc.size == 0 {
			if err = rc.src.Close(); err != nil {
				return
			}

			rc.src = nil
		}

		if rc.buf.Len() == rc.buf.Cap() {
			break
		}
	}

	return nil
}

func (rc *readCloser) Read(p []byte) (int, error) {
	if err := rc.read(); err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}

	return rc.buf.Read(p)
}

func (rc *readCloser) Close() (err error) {
	pool.Put(rc.buf)

	if rc.src != nil {
		if err = rc.src.Close(); err != nil {
			return
		}
	}

	return rc.rc.Close()
}

// NewReadCloser returns a new io.ReadCloser that reads the RVZ packed stream
// from the underlying io.ReadCloser rc. The offset of where this packed stream
// starts relative to the beginning of the uncompressed disc image is also
// required.
func NewReadCloser(rc io.ReadCloser, offset int64) (io.ReadCloser, error) {
	nrc := &readCloser{
		rc:     rc,
		offset: offset,
	}

	b, ok := pool.Get().(*bytes.Buffer)
	if ok {
		b.Reset()
	} else {
		b = new(bytes.Buffer)
		b.Grow(1 << 16)
	}

	nrc.buf = b

	return nrc, nil
}
