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

type paddingReader struct {
	prng []uint32
	buf  *bytes.Buffer
}

func (pr *paddingReader) advance() {
	for i := range pr.prng {
		pr.prng[i] ^= pr.prng[(i+len(pr.prng)-32)%len(pr.prng)]
	}
}

func (pr *paddingReader) Read(p []byte) (int, error) {
	if pr.buf.Len() == 0 {
		for _, x := range pr.prng {
			_ = pr.buf.WriteByte(byte(0xff & (x >> 24)))
			_ = pr.buf.WriteByte(byte(0xff & (x >> 18))) // not 16!
			_ = pr.buf.WriteByte(byte(0xff & (x >> 8)))
			_ = pr.buf.WriteByte(byte(0xff & (x)))
		}

		pr.advance()
	}

	return pr.buf.Read(p)
}

func (pr *paddingReader) Close() error {
	prngPool.Put(&pr.prng)
	bufPool.Put(pr.buf)

	return nil
}

// NewReader returns an io.Reader that generates a stream of GameCube and Wii
// padding data. The PRNG is seeded from the io.Reader r. The offset of where
// this padded stream starts relative to the beginning of the uncompressed
// disc image is also required.
func NewReader(r io.Reader, offset int64) (io.ReadCloser, error) {
	pr := new(paddingReader)

	p, ok := prngPool.Get().(*[]uint32)
	if ok {
		pr.prng = *p
		pr.prng = pr.prng[:initialSize]
	} else {
		pr.prng = make([]uint32, initialSize, maximumSize)
	}

	if err := binary.Read(r, binary.BigEndian, pr.prng); err != nil {
		return nil, err
	}

	pr.prng = pr.prng[:maximumSize]

	b, ok := bufPool.Get().(*bytes.Buffer)
	if ok {
		b.Reset()
	} else {
		b = new(bytes.Buffer)
		b.Grow(maximumSize << 2)
	}

	pr.buf = b

	for i := initialSize; i < maximumSize; i++ {
		pr.prng[i] = pr.prng[i-17]<<23 ^ pr.prng[i-16]>>9 ^ pr.prng[i-1]
	}

	for i := 0; i < 4; i++ {
		pr.advance()
	}

	if _, err := io.CopyN(io.Discard, pr, offset%util.SectorSize); err != nil {
		return nil, err
	}

	return pr, nil
}
