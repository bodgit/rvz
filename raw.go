package rvz

import (
	"fmt"
	"io"
)

// A rawReader decompresses a raw data area. Each 2 MiB block covers one or
// more whole groups so they can be prefetched in parallel.
type rawReader struct {
	i int
	r *reader
}

// fill decompresses the groups covering the i-th 2 MiB block of the raw data
// area into buf, returning how much of it is used.
func (rr *rawReader) fill(i int, buf []byte) (int, error) {
	x := rr.r.raw[rr.i]
	chunkSize := rr.r.disc.chunkSize(false)

	start := x.offset() + int64(i)*prefetchSize
	size := int(min(prefetchSize, x.end()-start))
	g := int(x.GroupIndex) + i*int(prefetchSize/chunkSize)

	// The last group may be shorter than the chunk size
	for off := 0; off < size; off, g = off+int(chunkSize), g+1 {
		if err := rr.readGroup(g, start+int64(off), buf[off:min(off+int(chunkSize), size)]); err != nil {
			return 0, err
		}
	}

	return size, nil
}

// readGroup decompresses group g, which starts at offset on the disc, into
// buf.
func (rr *rawReader) readGroup(g int, offset int64, buf []byte) error {
	gr, _, err := rr.r.groupReader(g, offset, false)
	if err != nil {
		return err
	}

	defer func() {
		_ = gr.Close()
	}()

	if _, err := io.ReadFull(gr, buf); err != nil {
		return fmt.Errorf("rvz: reading raw data: %w", err)
	}

	return nil
}

func newRawReader(r *reader, i int) io.Reader {
	rr := &rawReader{
		i: i,
		r: r,
	}

	x := r.raw[i]
	blocks := int((x.end() - x.offset() + prefetchSize - 1) / prefetchSize)

	return newPrefetcher(blocks, rr.fill)
}
