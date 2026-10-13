package padding_test

import (
	"bytes"
	"io"
	"math/rand/v2"
	"testing"

	"github.com/bodgit/rvz/internal/padding"
	"github.com/bodgit/rvz/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generate returns n bytes of padding from the seed, starting offset bytes
// into a sector.
func generate(t *testing.T, seed []byte, offset, n int) []byte {
	t.Helper()

	rc, err := padding.NewReadCloser(bytes.NewReader(seed), int64(offset))
	require.NoError(t, err)

	defer func() {
		_ = rc.Close()
	}()

	b := make([]byte, n)
	_, err = io.ReadFull(rc, b)
	require.NoError(t, err)

	return b
}

func TestSeed(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name      string
		offset, n int
	}{
		{"start of sector", 0, util.SectorSize},
		{"one block", 0, bufferSize * 4},
		{"word aligned", 0x1234, util.SectorSize - 0x1234},
		{"not word aligned", 0x1235, util.SectorSize - 0x1235},
		{"end of block", bufferSize*4 - 1, 3 * bufferSize * 4},
		{"near end of sector", util.SectorSize - 3*bufferSize*4 - 2, 3*bufferSize*4 + 2},
		{"later sector", 3*util.SectorSize + 777, 5000},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			want := generate(t, seed(), table.offset, table.n)

			got, n := padding.Seed(want, table.offset)
			assert.Equal(t, table.n, n)

			// Two bits of the seed can't be recovered, so compare
			// what it generates rather than the seed itself
			assert.True(t, bytes.Equal(want, generate(t, got[:], table.offset, table.n)),
				"recovered seed doesn't generate the same padding")
		})
	}
}

func TestSeedPartial(t *testing.T) {
	t.Parallel()

	const offset, n = 0x400, 10000

	// Padding followed by something else
	b := generate(t, seed(), offset, n)
	copy(b[6000:], bytes.Repeat([]byte{0xaa}, 100))

	_, got := padding.Seed(b, offset)
	assert.Equal(t, 6000, got)
}

// TestSeedZeroes checks zeroes are found to be padding from a seed of
// zeroes, which is why the packer skips them first.
func TestSeedZeroes(t *testing.T) {
	t.Parallel()

	seed, n := padding.Seed(make([]byte, util.SectorSize), 0)
	assert.Equal(t, util.SectorSize, n)
	assert.Equal(t, [padding.SeedSize]byte{}, seed)
}

func TestSeedNotPadding(t *testing.T) {
	t.Parallel()

	//nolint:gosec // reproducible test data
	r := rand.New(rand.NewPCG(3, 4))

	random := make([]byte, util.SectorSize)
	for i := range random {
		random[i] = byte(0xff & r.Uint32())
	}

	tables := []struct {
		name string
		b    []byte
	}{
		{"random", random},
		{"too short", generate(t, seed(), 0, bufferSize*4-1)},
		{"empty", nil},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			_, n := padding.Seed(table.b, 0)
			assert.Zero(t, n)
		})
	}
}
