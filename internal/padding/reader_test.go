package padding_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"testing/iotest"

	"github.com/bodgit/rvz/internal/padding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	seedSize   = 17
	bufferSize = 521
	sectorSize = 0x8000
)

func seed() []byte {
	b := make([]byte, seedSize*4)
	for i := range b {
		b[i] = byte(0xff & (i*37 + 11))
	}

	return b
}

// reference generates n bytes of padding the slow, obvious way, starting at
// the beginning of the sector containing offset.
func reference(t *testing.T, n int) []byte {
	t.Helper()

	prng := make([]uint32, bufferSize)
	require.NoError(t, binary.Read(bytes.NewReader(seed()), binary.BigEndian, prng[:seedSize]))

	for i := seedSize; i < bufferSize; i++ {
		prng[i] = prng[i-17]<<23 ^ prng[i-16]>>9 ^ prng[i-1]
	}

	advance := func() {
		for i := range prng {
			prng[i] ^= prng[(i+bufferSize-32)%bufferSize]
		}
	}

	for range 4 {
		advance()
	}

	out := make([]byte, 0, n+bufferSize*4)
	for len(out) < n {
		for _, x := range prng {
			out = append(out, byte(0xff&(x>>24)), byte(0xff&(x>>18)), byte(0xff&(x>>8)), byte(0xff&x))
		}

		advance()
	}

	return out[:n]
}

func TestReadCloser(t *testing.T) {
	t.Parallel()

	const size = 3 * sectorSize

	want := reference(t, sectorSize+size)

	tables := []struct {
		name   string
		offset int64
		wrap   func(io.Reader) io.Reader
	}{
		{"start", 0, func(r io.Reader) io.Reader { return r }},
		{"part way", 12345, func(r io.Reader) io.Reader { return r }},
		{"end of block", bufferSize * 4, func(r io.Reader) io.Reader { return r }},
		{"end of sector", sectorSize - 1, func(r io.Reader) io.Reader { return r }},
		{"next sector", 5*sectorSize + 999, func(r io.Reader) io.Reader { return r }},
		{"one byte at a time", 777, iotest.OneByteReader},
		{"half reads", 2083, iotest.HalfReader},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			rc, err := padding.NewReadCloser(bytes.NewReader(seed()), table.offset)
			require.NoError(t, err)

			got := make([]byte, size)
			_, err = io.ReadFull(table.wrap(rc), got)
			require.NoError(t, err)

			start := table.offset % sectorSize
			assert.True(t, bytes.Equal(want[start:start+size], got), "padding doesn't match")
			assert.NoError(t, rc.Close())
		})
	}
}

func TestReadCloserShortSeed(t *testing.T) {
	t.Parallel()

	_, err := padding.NewReadCloser(bytes.NewReader(seed()[:10]), 0)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func BenchmarkReadCloser(b *testing.B) {
	buf := make([]byte, 0x400)

	b.SetBytes(sectorSize)

	for b.Loop() {
		rc, err := padding.NewReadCloser(bytes.NewReader(seed()), 0)
		if err != nil {
			b.Fatal(err)
		}

		for range sectorSize / len(buf) {
			if _, err := io.ReadFull(rc, buf); err != nil {
				b.Fatal(err)
			}
		}

		_ = rc.Close()
	}
}
