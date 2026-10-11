// Package padding generates the pseudorandom padding data found on
// GameCube and Wii discs.
package padding

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/bodgit/rvz/internal/util"
)

const (
	initialSize = 17
	maximumSize = 521
	lag         = 32

	blockSize = maximumSize * 4 // bytes generated per advance
)

//nolint:gochecknoglobals
var pool = sync.Pool{
	New: func() any {
		return new(generator)
	},
}

type generator struct {
	prng [maximumSize]uint32
	buf  [blockSize]byte
}

type readCloser struct {
	g   *generator
	pos int
}

func (rc *readCloser) Read(p []byte) (int, error) {
	if rc.pos == blockSize {
		rc.fill()
	}

	n := copy(p, rc.g.buf[rc.pos:])
	rc.pos += n

	return n, nil
}

func (rc *readCloser) Close() error {
	if rc.g != nil {
		pool.Put(rc.g)
		rc.g = nil
	}

	return nil
}

// fill generates the next block of padding from the current state and then
// advances it.
func (rc *readCloser) fill() {
	buf := rc.g.buf[:]

	for i, x := range rc.g.prng {
		b := buf[i*4 : i*4+4]
		b[0] = byte(0xff & (x >> 24))
		b[1] = byte(0xff & (x >> 18)) // not 16!
		b[2] = byte(0xff & (x >> 8))
		b[3] = byte(0xff & x)
	}

	rc.advance()
	rc.pos = 0
}

func (rc *readCloser) advance() {
	prng := &rc.g.prng

	// The first few entries mix in entries from the end that haven't
	// been advanced yet, so the order matters
	for i := range lag {
		prng[i] ^= prng[i+maximumSize-lag]
	}

	for i := lag; i < maximumSize; i++ {
		prng[i] ^= prng[i-lag]
	}
}

// NewReadCloser returns an io.ReadCloser that generates a stream of GameCube
// and Wii padding data. The PRNG is seeded from the io.Reader r. The offset of
// where this padded stream starts relative to the beginning of the
// uncompressed disc image or the partition is also required.
func NewReadCloser(r io.Reader, offset int64) (io.ReadCloser, error) {
	g, ok := pool.Get().(*generator)
	if !ok {
		g = new(generator)
	}

	rc := &readCloser{g: g}

	if err := binary.Read(r, binary.BigEndian, g.prng[:initialSize]); err != nil {
		_ = rc.Close()

		return nil, fmt.Errorf("padding: reading seed: %w", err)
	}

	for i := initialSize; i < maximumSize; i++ {
		g.prng[i] = g.prng[i-17]<<23 ^ g.prng[i-16]>>9 ^ g.prng[i-1]
	}

	for range 4 {
		rc.advance()
	}

	// Skip whole blocks without generating them, the offset into a
	// sector is at most 32 KiB so this can't overflow
	skip := int(offset % util.SectorSize)

	for range skip / blockSize {
		rc.advance()
	}

	rc.fill()
	rc.pos = skip % blockSize

	return rc, nil
}
