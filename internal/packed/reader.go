package packed

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/bodgit/plumbing"
	"github.com/bodgit/rvz/internal/padding"
)

const (
	padded   uint32 = 1 << 31
	sizeMask        = padded - 1
)

type readCloser struct {
	rc     io.ReadCloser
	src    io.ReadCloser
	size   int64
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

	if rc.size == 0 {
		return rc.closeSrc()
	}

	return nil
}

func (rc *readCloser) closeSrc() error {
	err := rc.src.Close()
	rc.src = nil

	return err
}

//nolint:nakedret
func (rc *readCloser) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}

	// Skip any empty entries
	for rc.src == nil {
		if err = rc.nextReader(); err != nil {
			return
		}
	}

	if int64(len(p)) > rc.size {
		p = p[:rc.size]
	}

	n, err = rc.src.Read(p)
	rc.size -= int64(n)
	rc.offset += int64(n)

	switch {
	case rc.size == 0:
		if cerr := rc.closeSrc(); cerr != nil {
			return n, cerr
		}

		// There may be more entries to follow
		if errors.Is(err, io.EOF) {
			err = nil
		}
	case errors.Is(err, io.EOF):
		err = io.ErrUnexpectedEOF
	}

	return
}

func (rc *readCloser) Close() (err error) {
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
	return &readCloser{
		rc:     rc,
		offset: offset,
	}, nil
}
