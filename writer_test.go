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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sectorSize = 0x8000

// testDisc returns a disc image of size bytes that is recognised as a
// GameCube or Wii disc. Every other sector is filled with random data and
// the rest with a repeating pattern, so some groups compress and some don't.
func testDisc(size int, wii bool) []byte {
	b := make([]byte, size)

	//nolint:gosec // reproducible test data
	r := rand.New(rand.NewPCG(1, 2))

	for i := range b {
		if i/sectorSize%2 == 0 {
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
		{"GameCube", 4 * sectorSize, false, nil},
		{"Wii", 4 * sectorSize, true, nil},
		{"short last group", 5*sectorSize + 0x1234, false, []rvz.Option{rvz.WithChunkSize(rvz.ChunkSize64KiB)}},
		{"smallest chunks", 3 * sectorSize, false, []rvz.Option{rvz.WithChunkSize(rvz.ChunkSize32KiB)}},
		{"largest chunks", 3 * sectorSize, true, []rvz.Option{rvz.WithChunkSize(rvz.ChunkSize2MiB)}},
		{"within first sector", 0x1000, false, nil},
		{"no compression", 4 * sectorSize, false, []rvz.Option{rvz.WithCompression(rvz.MethodNone, 0)}},
		{"fastest", 4 * sectorSize, true, []rvz.Option{rvz.WithCompression(rvz.MethodZstandard, 1)}},
		{"best", 4 * sectorSize, false, []rvz.Option{rvz.WithCompression(rvz.MethodZstandard, 22)}},
		{"compressed groups", 64 * sectorSize, false, []rvz.Option{rvz.WithChunkSize(rvz.ChunkSize32KiB)}},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			iso := testDisc(table.size, table.wii)

			path, err := compress(t, iso, table.opts...)
			require.NoError(t, err)

			f, err := os.Open(path) //nolint:gosec // temporary file
			require.NoError(t, err)

			defer func() {
				_ = f.Close()
			}()

			r, err := rvz.NewReader(f)
			require.NoError(t, err)
			assert.Equal(t, int64(len(iso)), r.Size())

			got, err := io.ReadAll(r)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(iso, got), "disc image doesn't match")
		})
	}
}

// TestCompressSize checks that the compressible half of the test disc is
// stored compressed, unless compression is turned off.
func TestCompressSize(t *testing.T) {
	t.Parallel()

	const size = 64 * sectorSize

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

func TestCompressErrors(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name string
		iso  []byte
		opts []rvz.Option
	}{
		{"not a disc", make([]byte, sectorSize), nil},
		{"too small", testDisc(0x80, false)[:0x7f], nil},
		{"chunk size too small", testDisc(sectorSize, false), []rvz.Option{rvz.WithChunkSize(sectorSize / 2)}},
		{"chunk size too large", testDisc(sectorSize, false), []rvz.Option{rvz.WithChunkSize(128 * sectorSize)}},
		{"chunk size not a power of two", testDisc(sectorSize, false), []rvz.Option{rvz.WithChunkSize(3 * sectorSize)}},
		{"level too low", testDisc(sectorSize, false), []rvz.Option{rvz.WithCompression(rvz.MethodZstandard, 0)}},
		{"level too high", testDisc(sectorSize, false), []rvz.Option{rvz.WithCompression(rvz.MethodZstandard, 23)}},
		{"unsupported method", testDisc(sectorSize, false), []rvz.Option{rvz.WithCompression(rvz.MethodBzip2, 9)}},
		{"purge", testDisc(sectorSize, false), []rvz.Option{rvz.WithCompression(rvz.MethodPurge, 0)}},
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
			require.NoError(t, f.Close())

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
