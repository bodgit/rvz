package rvz

import (
	"errors"
	"fmt"
	"io"

	"github.com/bodgit/plumbing"
)

type rawReader struct {
	i, g   int
	r      *reader
	gr     io.ReadCloser
	offset int64
}

func (rr *rawReader) Read(p []byte) (int, error) {
	end := rr.r.raw[rr.i].end()
	if rr.offset == end {
		return 0, io.EOF
	}

	if rr.gr == nil {
		gr, _, err := rr.r.groupReader(rr.g, rr.offset, false)
		if err != nil {
			return 0, err
		}

		// The last group may be shorter than the chunk size
		rr.gr = plumbing.LimitReadCloser(gr, end-rr.offset)
	}

	n, err := rr.gr.Read(p)
	rr.offset += int64(n)

	switch {
	case err == nil:
		return n, nil
	case !errors.Is(err, io.EOF):
		return n, fmt.Errorf("rvz: reading raw data: %w", err)
	}

	// This group is finished, move on to the next one
	if err := rr.gr.Close(); err != nil {
		return n, fmt.Errorf("rvz: closing group: %w", err)
	}

	rr.g++
	rr.gr = nil

	return n, nil
}

func newRawReader(r *reader, i int) io.Reader {
	return &rawReader{
		i:      i,
		g:      int(r.raw[i].GroupIndex),
		r:      r,
		offset: r.raw[i].offset(),
	}
}
