package padding

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"

	"github.com/bodgit/rvz/internal/util"
)

const (
	initialSize = 17
	maximumSize = 521
)

//nolint:gochecknoglobals
var prngPool, bufPool sync.Pool

type readCloser struct {
	prng []uint32
	buf  *bytes.Buffer
}

func (rc *readCloser) advance() {
	for i := range rc.prng {
		rc.prng[i] ^= rc.prng[(i+len(rc.prng)-32)%len(rc.prng)]
	}
}

func (rc *readCloser) Read(p []byte) (int, error) {
	if rc.buf.Len() == 0 {
		for _, x := range rc.prng {
			_ = rc.buf.WriteByte(byte(0xff & (x >> 24)))
			_ = rc.buf.WriteByte(byte(0xff & (x >> 18))) // not 16!
			_ = rc.buf.WriteByte(byte(0xff & (x >> 8)))
			_ = rc.buf.WriteByte(byte(0xff & (x)))
		}

		rc.advance()
	}

	return rc.buf.Read(p)
}

func (rc *readCloser) Close() error {
	prngPool.Put(&rc.prng)
	bufPool.Put(rc.buf)

	return nil
}

// NewReadCloser returns an io.ReadCloser that generates a stream of GameCube
// and Wii padding data. The PRNG is seeded from the io.Reader r. The offset of
// where this padded stream starts relative to the beginning of the
// uncompressed disc image or the partition is also required.
func NewReadCloser(r io.Reader, offset int64) (io.ReadCloser, error) {
	rc := new(readCloser)

	p, ok := prngPool.Get().(*[]uint32)
	if ok {
		rc.prng = *p
		rc.prng = rc.prng[:initialSize]
	} else {
		rc.prng = make([]uint32, initialSize, maximumSize)
	}

	if err := binary.Read(r, binary.BigEndian, rc.prng); err != nil {
		return nil, err
	}

	rc.prng = rc.prng[:maximumSize]

	b, ok := bufPool.Get().(*bytes.Buffer)
	if ok {
		b.Reset()
	} else {
		b = new(bytes.Buffer)
		b.Grow(maximumSize << 2)
	}

	rc.buf = b

	for i := initialSize; i < maximumSize; i++ {
		rc.prng[i] = rc.prng[i-17]<<23 ^ rc.prng[i-16]>>9 ^ rc.prng[i-1]
	}

	for i := 0; i < 4; i++ {
		rc.advance()
	}

	if _, err := io.CopyN(io.Discard, rc, offset%util.SectorSize); err != nil {
		return nil, err
	}

	return rc, nil
}
