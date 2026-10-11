package rvz

import (
	"errors"
	"io"

	"github.com/bodgit/plumbing"
)

type rawReader struct {
	i, g   int
	r      *reader
	gr     io.ReadCloser
	offset int64
}

//nolint:nakedret
func (rr *rawReader) Read(p []byte) (n int, err error) {
	end := int64(rr.r.raw[rr.i].RawDataOff + rr.r.raw[rr.i].RawDataSize)
	if rr.offset == end {
		return n, io.EOF
	}

	if rr.gr == nil {
		if rr.gr, _, err = rr.r.groupReader(rr.g, rr.offset, false); err != nil {
			return
		}

		// The last group may be shorter than the chunk size
		rr.gr = plumbing.LimitReadCloser(rr.gr, end-rr.offset)
	}

	n, err = rr.gr.Read(p)
	rr.offset += int64(n)

	if err != nil {
		if !errors.Is(err, io.EOF) {
			return
		}

		if err = rr.gr.Close(); err != nil {
			return
		}

		rr.g++

		rr.gr, err = nil, nil
	}

	return
}

func newRawReader(r *reader, i int) io.Reader {
	return &rawReader{
		i:      i,
		g:      int(r.raw[i].GroupIndex),
		r:      r,
		offset: int64(r.raw[i].RawDataOff),
	}
}
