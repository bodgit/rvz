package padding

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	initialSize = 17
	maximumSize = 521
)

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

// NewReader returns an io.Reader that generates a stream of GameCube and Wii
// padding data. The PRNG is seeded from the io.Reader r. The offset if where
// this padded stream starts relative to the beginning of the uncompressed
// disc image is also required.
func NewReader(r io.Reader, offset int64) (io.Reader, error) {
	pr := new(paddingReader)

	pr.prng = make([]uint32, initialSize, maximumSize)
	if err := binary.Read(r, binary.BigEndian, pr.prng); err != nil {
		return nil, err
	}

	pr.prng = pr.prng[:cap(pr.prng)]

	pr.buf = new(bytes.Buffer)
	pr.buf.Grow(maximumSize << 2)

	for i := initialSize; i < maximumSize; i++ {
		pr.prng[i] = pr.prng[i-17]<<23 ^ pr.prng[i-16]>>9 ^ pr.prng[i-1]
	}

	for i := 0; i < 4; i++ {
		pr.advance()
	}

	if _, err := io.CopyN(io.Discard, pr, offset%0x8000); err != nil {
		return nil, err
	}

	return pr, nil
}
