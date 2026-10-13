// Package packed implements a reader and writer for the RVZ packed stream,
// which interleaves stored data with seeds for regenerating padding.
package packed

import (
	"encoding/binary"
	"errors"
	"fmt"
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

func (rc *readCloser) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Skip any empty entries
	for rc.src == nil {
		if err := rc.nextReader(); err != nil {
			return 0, err
		}
	}

	if int64(len(p)) > rc.size {
		p = p[:rc.size]
	}

	n, err := rc.src.Read(p)
	rc.size -= int64(n)
	rc.offset += int64(n)

	switch {
	case rc.size == 0:
		if err := rc.closeSrc(); err != nil {
			return n, err
		}

		// There may be more entries to follow
		if errors.Is(err, io.EOF) {
			err = nil
		}
	case errors.Is(err, io.EOF):
		err = io.ErrUnexpectedEOF
	}

	return n, err
}

func (rc *readCloser) Close() error {
	if rc.src != nil {
		if err := rc.closeSrc(); err != nil {
			return err
		}
	}

	if err := rc.rc.Close(); err != nil {
		return fmt.Errorf("packed: %w", err)
	}

	return nil
}

func (rc *readCloser) nextReader() error {
	var size uint32
	if err := binary.Read(rc.rc, binary.BigEndian, &size); err != nil {
		// A clean end of the stream must be returned as is
		if errors.Is(err, io.EOF) {
			return io.EOF
		}

		return fmt.Errorf("packed: reading entry size: %w", err)
	}

	rc.size = int64(size & sizeMask)

	if size&padded == padded {
		nrc, err := padding.NewReadCloser(rc.rc, rc.offset)
		if err != nil {
			return fmt.Errorf("packed: %w", err)
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

	if err != nil {
		return fmt.Errorf("packed: closing entry: %w", err)
	}

	return nil
}

// NewReadCloser returns a new io.ReadCloser that reads the RVZ packed stream
// from the underlying io.ReadCloser rc. The offset of where this packed stream
// starts relative to the beginning of the uncompressed disc image is also
// required.
func NewReadCloser(rc io.ReadCloser, offset int64) io.ReadCloser {
	return &readCloser{
		rc:     rc,
		offset: offset,
	}
}
