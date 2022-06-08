package rvz

import (
	"errors"
	"io"
)

type rawReader struct {
	i, g   int
	r      *reader
	gr     io.ReadCloser
	offset int64
}

func (rr *rawReader) lastGroup() bool {
	return rr.g == int(rr.r.raw[rr.i].GroupIndex+rr.r.raw[rr.i].NumGroup)
}

func (rr *rawReader) Read(p []byte) (n int, err error) {
	if rr.gr == nil {
		if rr.gr, _, err = rr.r.groupReader(rr.g, rr.offset, false); err != nil {
			return
		}
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

		// Last group in the raw area?
		if rr.lastGroup() {
			return n, io.EOF
		}

		if rr.gr, _, err = rr.r.groupReader(rr.g, rr.offset, false); err != nil {
			return
		}
	}

	return n, nil
}

func newRawReader(r *reader, i int) io.Reader {
	return &rawReader{
		i:      i,
		g:      int(r.raw[i].GroupIndex),
		r:      r,
		offset: int64(r.raw[i].RawDataOff),
	}
}
