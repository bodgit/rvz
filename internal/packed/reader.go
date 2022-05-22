package packed

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/bodgit/rvz/internal/padding"
)

const (
	padded   uint32 = 1 << 31
	sizeMask        = padded - 1
)

type readCloser struct {
	rc     io.ReadCloser
	src    io.Reader
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

	var nr io.Reader

	if size&padded == padded {
		nr, err = padding.NewReader(rc.rc, rc.offset)
		if err != nil {
			return err
		}
	} else {
		nr = rc.rc
	}

	rc.src = io.LimitReader(nr, rc.size)

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

func (rc *readCloser) Close() error {
	return rc.rc.Close()
}

// NewReadCloser returns a new io.ReadCloser that reads the RVZ packed stream
// from the underlying io.ReadCloser rc. The offset of where this packed stream
// starts relative to the beginning of the uncompressed disc image is also
// required.
func NewReadCloser(rc io.ReadCloser, offset int64) (io.ReadCloser, error) {
	nrc := &readCloser{
		rc:     rc,
		buf:    new(bytes.Buffer),
		offset: offset,
	}
	nrc.buf.Grow(1 << 16)

	return nrc, nil
}
