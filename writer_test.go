package rvz_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/bodgit/rvz"
	"github.com/bodgit/rvz/internal/padding"
	"github.com/bodgit/rvz/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDisc returns a disc image of size bytes that is recognised as a
// GameCube or Wii disc. Every other sector is filled with random data and
// the rest with a repeating pattern, so some groups compress and some don't.
func testDisc(size int, wii bool) []byte {
	b := make([]byte, size)

	//nolint:gosec // reproducible test data
	r := rand.New(rand.NewPCG(1, 2))

	for i := range b {
		if i/util.SectorSize%2 == 0 {
			b[i] = byte(0xff & r.Uint32())
		} else {
			b[i] = byte(i % 251)
		}
	}

	// Clear both magic numbers and then set the right one
	clear(b[0x18:0x20])

	if wii {
		binary.BigEndian.PutUint32(b[0x18:], 0x5d1c9ea3)
	} else {
		binary.BigEndian.PutUint32(b[0x1c:], 0xc2339f3d)
	}

	return b
}

// readAll returns the disc image read from the RVZ image at path.
func readAll(t *testing.T, path string) []byte {
	t.Helper()

	f, err := os.Open(path) //nolint:gosec // temporary file
	require.NoError(t, err)

	defer func() {
		_ = f.Close()
	}()

	r, err := rvz.NewReader(f)
	require.NoError(t, err)

	b, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, r.Size(), int64(len(b)))

	return b
}

// compress compresses iso into a temporary file and returns its path.
func compress(t *testing.T, iso []byte, opts ...rvz.Option) (string, error) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test"+rvz.Extension)

	f, err := os.Create(path) //nolint:gosec // temporary file
	require.NoError(t, err)

	defer func() {
		require.NoError(t, f.Close())
	}()

	return path, rvz.Compress(f, bytes.NewReader(iso), int64(len(iso)), opts...) //nolint:wrapcheck
}

func TestCompress(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name string
		size int
		wii  bool
		opts []rvz.Option
	}{
		{"GameCube", 4 * util.SectorSize, false, nil},
		{"Wii", 4 * util.SectorSize, true, nil},
		{"short last group", 5*util.SectorSize + 0x1234, false, []rvz.Option{rvz.WithChunkSize(rvz.ChunkSize64KiB)}},
		{"smallest chunks", 3 * util.SectorSize, false, []rvz.Option{rvz.WithChunkSize(rvz.ChunkSize32KiB)}},
		{"largest chunks", 3 * util.SectorSize, true, []rvz.Option{rvz.WithChunkSize(rvz.ChunkSize2MiB)}},
		{"within first sector", 0x1000, false, nil},
		{"no compression", 4 * util.SectorSize, false, []rvz.Option{rvz.WithCompression(rvz.MethodNone, 0)}},
		{"fastest", 4 * util.SectorSize, true, []rvz.Option{rvz.WithCompression(rvz.MethodZstandard, 1)}},
		{"best", 4 * util.SectorSize, false, []rvz.Option{rvz.WithCompression(rvz.MethodZstandard, 22)}},
		{"compressed groups", 64 * util.SectorSize, false, []rvz.Option{rvz.WithChunkSize(rvz.ChunkSize32KiB)}},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			iso := testDisc(table.size, table.wii)

			path, err := compress(t, iso, table.opts...)
			require.NoError(t, err)

			got := readAll(t, path)
			assert.True(t, bytes.Equal(iso, got), "disc image doesn't match")
		})
	}
}

// TestCompressSize checks that the compressible half of the test disc is
// stored compressed, unless compression is turned off.
func TestCompressSize(t *testing.T) {
	t.Parallel()

	const size = 64 * util.SectorSize

	tables := []struct {
		name     string
		opts     []rvz.Option
		min, max int64
	}{
		{"default", nil, size / 2, size * 6 / 10},
		{"no compression", []rvz.Option{rvz.WithCompression(rvz.MethodNone, 0)}, size, size * 11 / 10},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			path, err := compress(t, testDisc(size, false), table.opts...)
			require.NoError(t, err)

			fi, err := os.Stat(path)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, fi.Size(), table.min)
			assert.LessOrEqual(t, fi.Size(), table.max)
		})
	}
}

// TestCompressReuse checks that chunks of zeroes take no space and chunks
// where every byte is the same are stored once for each size.
func TestCompressReuse(t *testing.T) {
	t.Parallel()

	// Random, zero, 0xff, zero, 0xff, random and then half a sector of
	// 0xff, which can't reuse the earlier groups as it's shorter
	iso := testDisc(6*util.SectorSize+util.SectorSize/2, false)

	for _, i := range []int{1, 3} {
		clear(iso[i*util.SectorSize : (i+1)*util.SectorSize])
	}

	for _, i := range []int{2, 4, 6} {
		copy(iso[i*util.SectorSize:], bytes.Repeat([]byte{0xff}, util.SectorSize))
	}

	path, err := compress(t, iso, rvz.WithChunkSize(rvz.ChunkSize32KiB), rvz.WithCompression(rvz.MethodNone, 0))
	require.NoError(t, err)

	got := readAll(t, path)
	assert.True(t, bytes.Equal(iso, got), "disc image doesn't match")

	// One sector for the headers and tables, two random sectors, one
	// sector of 0xff and the half sector of 0xff
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, int64(4*util.SectorSize+util.SectorSize/2), fi.Size())
}

// TestCompressPadding checks that padding is stored as seeds, so a disc that
// is mostly padding is tiny once compressed.
func TestCompressPadding(t *testing.T) {
	t.Parallel()

	const sectors = 16

	// The first sector is the disc header, then each sector is padding
	// generated from its own seed after a few zeroes
	iso := testDisc(sectors*util.SectorSize, false)

	for i := 1; i < sectors; i++ {
		seed := testDisc(padding.SeedSize+0x20, false)[0x20:]
		skip := i % 3 * 12

		rc, err := padding.NewReadCloser(bytes.NewReader(seed), int64(i*util.SectorSize+skip))
		require.NoError(t, err)

		clear(iso[i*util.SectorSize : i*util.SectorSize+skip])
		_, err = io.ReadFull(rc, iso[i*util.SectorSize+skip:(i+1)*util.SectorSize])
		require.NoError(t, err)
		require.NoError(t, rc.Close())
	}

	for _, method := range []uint32{rvz.MethodNone, rvz.MethodZstandard} {
		path, err := compress(t, iso, rvz.WithCompression(method, rvz.DefaultLevel))
		require.NoError(t, err)

		assert.True(t, bytes.Equal(iso, readAll(t, path)), "disc image doesn't match")

		// The headers and tables, the random first sector, and a seed
		// for each other sector
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Less(t, fi.Size(), int64(2*util.SectorSize+sectors*100))
	}
}

func TestCompressErrors(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name string
		iso  []byte
		opts []rvz.Option
	}{
		{"not a disc", make([]byte, util.SectorSize), nil},
		{"too small", testDisc(0x80, false)[:0x7f], nil},
		{"chunk size too small", testDisc(util.SectorSize, false), []rvz.Option{rvz.WithChunkSize(util.SectorSize / 2)}},
		{"chunk size too large", testDisc(util.SectorSize, false), []rvz.Option{rvz.WithChunkSize(128 * util.SectorSize)}},
		{
			"chunk size not a power of two",
			testDisc(util.SectorSize, false),
			[]rvz.Option{rvz.WithChunkSize(3 * util.SectorSize)},
		},
		{"level too low", testDisc(util.SectorSize, false), []rvz.Option{rvz.WithCompression(rvz.MethodZstandard, 0)}},
		{"level too high", testDisc(util.SectorSize, false), []rvz.Option{rvz.WithCompression(rvz.MethodZstandard, 23)}},
		{"unsupported method", testDisc(util.SectorSize, false), []rvz.Option{rvz.WithCompression(rvz.MethodBzip2, 9)}},
		{"purge", testDisc(util.SectorSize, false), []rvz.Option{rvz.WithCompression(rvz.MethodPurge, 0)}},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			_, err := compress(t, table.iso, table.opts...)
			assert.Error(t, err)
		})
	}
}

// TestRoundTrip decompresses each test image, compresses it again and checks
// the result against the datfile. Each image needs twice its uncompressed
// size in temporary space so they are run one at a time.
//
//nolint:paralleltest
func TestRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	for _, disc := range discs {
		t.Run(disc.name, func(t *testing.T) {
			dir := t.TempDir()

			iso := decompressTo(t, filepath.Join("testdata", disc.file+rvz.Extension), filepath.Join(dir, "disc.iso"))

			defer func() {
				_ = iso.Close()
			}()

			fi, err := iso.Stat()
			require.NoError(t, err)

			path := filepath.Join(dir, "disc"+rvz.Extension)

			f, err := os.Create(path) //nolint:gosec // temporary file
			require.NoError(t, err)

			require.NoError(t, rvz.Compress(f, iso, fi.Size()))

			out, err := f.Stat()
			require.NoError(t, err)
			require.NoError(t, f.Close())

			t.Logf("compressed %d bytes to %d bytes", fi.Size(), out.Size())

			assert.Equal(t, redumpSHA1(t, disc.dat, disc.file), readSHA1(t, path))
		})
	}
}

// decompressTo decompresses the RVZ image at src to dst, returning dst
// opened for reading.
func decompressTo(t *testing.T, src, dst string) *os.File {
	t.Helper()

	in, err := os.Open(src) //nolint:gosec // only test data is read
	require.NoError(t, err)

	defer func() {
		_ = in.Close()
	}()

	r, err := rvz.NewReader(in)
	require.NoError(t, err)

	out, err := os.Create(dst) //nolint:gosec // temporary file
	require.NoError(t, err)

	if _, err := io.Copy(out, r); err != nil {
		_ = out.Close()

		t.Fatal(err)
	}

	_, err = out.Seek(0, io.SeekStart)
	require.NoError(t, err)

	return out
}
