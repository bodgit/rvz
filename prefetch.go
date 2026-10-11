package rvz

import (
	"io"
	"runtime"
	"sync"
)

// prefetchSize is the size of each block a prefetcher produces.
const prefetchSize = groupSize // 2 MiB

//nolint:gochecknoglobals
var prefetchPool = sync.Pool{
	New: func() any {
		b := make([]byte, prefetchSize)

		return &b
	},
}

// A fillFunc fills buf with the i-th block, returning how much of it is used.
// It is called concurrently so must only use immutable state.
type fillFunc func(i int, buf []byte) (int, error)

type prefetch struct {
	buf  *[]byte
	size int
	err  error
	done chan struct{}
}

// A prefetcher is an io.Reader that produces a sequence of blocks in the
// background, with up to GOMAXPROCS blocks running ahead of the reader. The
// blocks are returned in order. Goroutines are only started from Read so if
// the reader is abandoned they finish and exit.
type prefetcher struct {
	fill fillFunc

	next    int         // next block to start
	blocks  int         // total number of blocks
	pending []*prefetch // started but not yet read, in order
	buf     *[]byte     // buffer of the block being read
	data    []byte      // unread data in buf
	err     error
}

func newPrefetcher(blocks int, fill fillFunc) *prefetcher {
	return &prefetcher{
		fill:   fill,
		blocks: blocks,
	}
}

func (p *prefetcher) Read(b []byte) (int, error) {
	if len(p.data) == 0 {
		if err := p.nextBlock(); err != nil {
			return 0, err
		}
	}

	n := copy(b, p.data)
	p.data = p.data[n:]

	return n, nil
}

// nextBlock waits for the next block and makes it available to Read.
func (p *prefetcher) nextBlock() error {
	if p.err != nil {
		return p.err
	}

	// The current block has been read so its buffer can be reused
	if p.buf != nil {
		prefetchPool.Put(p.buf)
		p.buf, p.data = nil, nil
	}

	p.start()

	if len(p.pending) == 0 {
		return io.EOF
	}

	f := p.pending[0]
	p.pending = p.pending[1:]

	<-f.done

	if f.err != nil {
		p.err = f.err

		return p.err
	}

	p.buf = f.buf
	p.data = (*f.buf)[:f.size]

	// Start another block to replace this one
	p.start()

	return nil
}

// start fills blocks in the background until enough are in flight.
func (p *prefetcher) start() {
	for p.next < p.blocks && len(p.pending) < runtime.GOMAXPROCS(0) {
		buf, ok := prefetchPool.Get().(*[]byte)
		if !ok {
			b := make([]byte, prefetchSize)
			buf = &b
		}

		f := &prefetch{
			buf:  buf,
			done: make(chan struct{}),
		}

		go func(i int) {
			defer close(f.done)

			f.size, f.err = p.fill(i, *f.buf)
		}(p.next)

		p.pending = append(p.pending, f)
		p.next++
	}
}
