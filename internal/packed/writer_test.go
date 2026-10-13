package packed_test

import (
	"bytes"
	"io"
	"math/rand/v2"
	"testing"

	"github.com/bodgit/rvz/internal/packed"
	"github.com/bodgit/rvz/internal/padding"
	"github.com/bodgit/rvz/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sectorPadding returns the padding from the seed for the sector starting at
// offset, after skipping some bytes.
func sectorPadding(t *testing.T, offset int64, skip int) []byte {
	t.Helper()

	rc, err := padding.NewReadCloser(bytes.NewReader(seed()), offset+int64(skip))
	require.NoError(t, err)

	defer func() {
		_ = rc.Close()
	}()

	b := make([]byte, util.SectorSize-skip)
	_, err = io.ReadFull(rc, b)
	require.NoError(t, err)

	return b
}

func randomBytes(n int) []byte {
	//nolint:gosec // reproducible test data
	r := rand.New(rand.NewPCG(5, 6))

	b := make([]byte, n)
	for i := range b {
		b[i] = byte(0xff & r.Uint32())
	}

	return b
}

func unpack(t *testing.T, b []byte, offset int64) []byte {
	t.Helper()

	rc := packed.NewReadCloser(io.NopCloser(bytes.NewReader(b)), offset)

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	return got
}

func TestPack(t *testing.T) {
	t.Parallel()

	const offset = 5 * util.SectorSize

	// A sector of zeroes then padding, a sector of data, and a sector
	// of padding cut short
	chunk := make([]byte, 0, 3*util.SectorSize)
	chunk = append(chunk, make([]byte, 20)...)
	chunk = append(chunk, sectorPadding(t, offset, 20)...)
	chunk = append(chunk, randomBytes(util.SectorSize)...)
	chunk = append(chunk, sectorPadding(t, offset+2*util.SectorSize, 0)[:util.SectorSize/2]...)

	tables := []struct {
		name        string
		chunk       []byte
		compression bool
		ok          bool
		max         int
	}{
		{"padding", chunk, true, true, util.SectorSize + 1000},
		{"padding without compression", chunk, false, true, util.SectorSize + 1000},
		{"no padding", randomBytes(util.SectorSize), true, false, 0},
		{"zeroes", make([]byte, util.SectorSize), true, false, 0},
		{"zeroes without compression", make([]byte, util.SectorSize), false, true, 100},
		{"short", chunk[:50], false, false, 0},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			b, ok := packed.Pack(nil, table.chunk, offset, table.compression, nil)
			require.Equal(t, table.ok, ok)

			if !ok {
				assert.Empty(t, b)

				return
			}

			assert.LessOrEqual(t, len(b), table.max)
			assert.True(t, bytes.Equal(table.chunk, unpack(t, b, offset)), "unpacked data doesn't match")
		})
	}
}

// TestPackAppends checks Pack appends to dst rather than overwriting it.
func TestPackAppends(t *testing.T) {
	t.Parallel()

	chunk := sectorPadding(t, 0, 0)

	b, ok := packed.Pack([]byte("prefix"), chunk, 0, true, nil)
	require.True(t, ok)
	assert.Equal(t, []byte("prefix"), b[:6])
	assert.True(t, bytes.Equal(chunk, unpack(t, b[6:], 0)))
}

// file is a single file on the disc.
type file struct {
	start, end int64
}

func (f file) End(offset int64) (int64, bool) {
	if offset >= f.start && offset < f.end {
		return f.end, true
	}

	return 0, false
}

// TestPackAfterFile checks padding after a file that ends part way through a
// sector is only found when where the file ends is known.
func TestPackAfterFile(t *testing.T) {
	t.Parallel()

	const (
		offset  = 7 * util.SectorSize
		fileEnd = 0x1003
		zeroes  = 13
	)

	// The sector is seeded at its start, so the padding after the file is
	// a continuation of that
	chunk := sectorPadding(t, offset, 0)
	copy(chunk, randomBytes(fileEnd))
	clear(chunk[fileEnd : fileEnd+zeroes])

	_, ok := packed.Pack(nil, chunk, offset, true, nil)
	assert.False(t, ok, "padding found without knowing where the file ends")

	b, ok := packed.Pack(nil, chunk, offset, true, file{start: offset, end: offset + fileEnd})
	require.True(t, ok)
	assert.Less(t, len(b), fileEnd+zeroes+200)
	assert.True(t, bytes.Equal(chunk, unpack(t, b, offset)), "unpacked data doesn't match")
}
