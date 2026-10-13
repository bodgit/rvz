package rvz

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/bodgit/rvz/internal/padding"
	"github.com/bodgit/rvz/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	wiiTestPartition  = 0x50000
	wiiTestDataOffset = 0x20000
	wiiTestDataStart  = wiiTestPartition + wiiTestDataOffset
	wiiTestSectors    = clusters + 6 // a full block and part of another
	wiiTestFSTOffset  = 0x2440
	wiiTestBadSector  = 3 // has a wrong H0 hash
)

//nolint:gochecknoglobals
var (
	testCommonKey = [aes.BlockSize]byte{0xc0, 0xff, 0xee}
	testTitleKey  = [aes.BlockSize]byte{0x7e, 0x57}
	testTitleID   = [8]byte{0, 1, 0, 0, 'T', 'E', 'S', 'T'}
)

// testFile is a file in the test partition, in its decrypted data.
type testFile struct {
	offset, size int
}

//nolint:gochecknoglobals
var testFiles = []testFile{
	{0x10000, 0x1003},  // ends part way through a sector
	{0x40000, 0x12345}, // spans sectors
}

func randomFill(r *rand.Rand, b []byte) {
	for i := range b {
		b[i] = byte(0xff & r.Uint32())
	}
}

// testPartitionData returns the decrypted data of the test partition. As on
// a real disc, it is padding seeded every 32 KiB, with the partition header,
// file system table and files written over it.
func testPartitionData(t *testing.T) []byte {
	t.Helper()

	//nolint:gosec // reproducible test data
	r := rand.New(rand.NewPCG(7, 8))
	data := make([]byte, wiiTestSectors*sectorDataSize)

	for offset := 0; offset < len(data); offset += util.SectorSize {
		seed := make([]byte, padding.SeedSize)
		randomFill(r, seed)

		rc, err := padding.NewReadCloser(bytes.NewReader(seed), int64(offset))
		require.NoError(t, err)

		_, err = io.ReadFull(rc, data[offset:min(offset+util.SectorSize, len(data))])
		require.NoError(t, err)
		require.NoError(t, rc.Close())
	}

	// The partition header points to the file system table
	clear(data[:0x440])
	binary.BigEndian.PutUint32(data[0x18:], wiiMagic)

	fstSize := (len(testFiles) + 1) * 12

	binary.BigEndian.PutUint32(data[0x424:], wiiTestFSTOffset>>2)
	binary.BigEndian.PutUint32(data[0x428:], uint32(fstSize>>2)) //nolint:gosec // test data is small

	table := data[wiiTestFSTOffset : wiiTestFSTOffset+fstSize]
	clear(table)
	table[0] = 1
	binary.BigEndian.PutUint32(table[8:], uint32(len(testFiles)+1)) //nolint:gosec // test data is small

	for i, f := range testFiles {
		e := table[(i+1)*12:]
		binary.BigEndian.PutUint32(e[4:], uint32(f.offset>>2)) //nolint:gosec // test data is small
		binary.BigEndian.PutUint32(e[8:], uint32(f.size))      //nolint:gosec // test data is small

		randomFill(r, data[f.offset:f.offset+f.size])

		// A few zeroes typically follow a file
		clear(data[f.offset+f.size : f.offset+f.size+13])
	}

	return data
}

// testWiiDisc returns a Wii disc image with a single partition encrypted
// with the test keys, whose ticket names the common key index, and the
// decrypted partition data.
func testWiiDisc(t *testing.T, index byte) ([]byte, []byte) {
	t.Helper()

	data := testPartitionData(t)
	disc := make([]byte, wiiTestDataStart+wiiTestSectors*util.SectorSize+util.SectorSize)

	binary.BigEndian.PutUint32(disc[wiiMagicOffset:], wiiMagic)

	// One partition in the first group of the partition table
	binary.BigEndian.PutUint32(disc[partitionTableOffset:], 1)
	binary.BigEndian.PutUint32(disc[partitionTableOffset+4:], (partitionTableOffset+0x20)>>2)
	binary.BigEndian.PutUint32(disc[partitionTableOffset+0x20:], wiiTestPartition>>2)

	// The ticket and where the partition data is
	p := disc[wiiTestPartition:]
	binary.BigEndian.PutUint32(p, partitionSignature)
	copy(p[ticketTitleID:], testTitleID[:])
	p[ticketCommonKeyIndex] = index

	common, err := aes.NewCipher(testCommonKey[:])
	require.NoError(t, err)

	var titleIV [aes.BlockSize]byte

	copy(titleIV[:], testTitleID[:])
	cipher.NewCBCEncrypter(common, titleIV[:]).CryptBlocks(p[ticketTitleKey:ticketTitleKey+aes.BlockSize], testTitleKey[:])

	binary.BigEndian.PutUint32(p[partitionDataInfo:], wiiTestDataOffset>>2)
	binary.BigEndian.PutUint32(p[partitionDataInfo+4:], wiiTestSectors*util.SectorSize>>2)

	block, err := aes.NewCipher(testTitleKey[:])
	require.NoError(t, err)

	e := newSectorEncrypter(block)

	// Each 2 MiB block has its hashes calculated with any sectors beyond
	// the end as zeroes, and is then encrypted
	for first := 0; first < wiiTestSectors; first += clusters {
		sectors := min(clusters, wiiTestSectors-first)
		buf := make([]byte, groupSize)

		for s := range sectors {
			copy(buf[s*util.SectorSize+hashSize:(s+1)*util.SectorSize], data[(first+s)*sectorDataSize:])
		}

		writeHashes(buf)

		if first == 0 {
			buf[wiiTestBadSector*util.SectorSize+5*20] ^= 0xff
		}

		for s := range sectors {
			sector := buf[s*util.SectorSize : (s+1)*util.SectorSize]
			e.encrypt(sector) //nolint:gosec // the disc format requires a zero IV
			copy(disc[wiiTestDataStart+(first+s)*util.SectorSize:], sector)
		}
	}

	// Something after the partition
	//nolint:gosec // reproducible test data
	randomFill(rand.New(rand.NewPCG(9, 10)), disc[len(disc)-util.SectorSize:])

	return disc, data
}

// compressTest compresses disc and returns the RVZ image.
func compressTest(t *testing.T, disc []byte, opts ...Option) []byte {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test"+Extension)

	f, err := os.Create(path) //nolint:gosec // temporary file
	require.NoError(t, err)

	require.NoError(t, Compress(f, bytes.NewReader(disc), int64(len(disc)), opts...))
	require.NoError(t, f.Close())

	b, err := os.ReadFile(path) //nolint:gosec // temporary file
	require.NoError(t, err)

	return b
}

func TestCompressWii(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name       string
		index      byte // the common key the disc uses
		opts       []Option
		partitions int
	}{
		{"no key", CommonKeyRetail, nil, 0},
		{"key", CommonKeyRetail, []Option{WithCommonKey(CommonKeyRetail, testCommonKey)}, 1},
		{"wrong key", CommonKeyRetail, []Option{WithCommonKey(CommonKeyRetail, [aes.BlockSize]byte{1})}, 0},
		{"key for another index", CommonKeyRetail, []Option{WithCommonKey(CommonKeyKorean, testCommonKey)}, 0},
		{"Korean key", CommonKeyKorean, []Option{WithCommonKey(CommonKeyKorean, testCommonKey)}, 1},
		{"vWii key", CommonKeyVWii, []Option{WithCommonKey(CommonKeyVWii, testCommonKey)}, 1},
		{"retail key for Korean disc", CommonKeyKorean, []Option{WithCommonKey(CommonKeyRetail, testCommonKey)}, 0},
		{"no compression", CommonKeyRetail, []Option{
			WithCommonKey(CommonKeyRetail, testCommonKey),
			WithCompression(MethodNone, 0),
		}, 1},
		{"smallest chunks", CommonKeyRetail, []Option{
			WithCommonKey(CommonKeyRetail, testCommonKey),
			WithChunkSize(ChunkSize32KiB),
		}, 1},
		{"largest chunks", CommonKeyRetail, []Option{
			WithCommonKey(CommonKeyRetail, testCommonKey),
			WithChunkSize(ChunkSize2MiB),
		}, 1},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			disc, _ := testWiiDisc(t, table.index)
			b := compressTest(t, disc, table.opts...)

			rd, err := NewReader(bytes.NewReader(b))
			require.NoError(t, err)

			got, err := io.ReadAll(rd)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(disc, got), "disc image doesn't match")

			r, ok := rd.(*reader)
			require.True(t, ok)
			require.Len(t, r.part, table.partitions)

			if table.partitions == 0 {
				return
			}

			// The data is split after the file system table, rounded
			// up to 2 MiB
			p := r.part[0]
			assert.Equal(t, testTitleKey, p.Key)
			assert.Equal(t, uint32(wiiTestDataStart/util.SectorSize), p.Data[0].FirstSector)
			assert.Equal(t, uint32(clusters), p.Data[0].NumSector)
			assert.Equal(t, uint32(wiiTestSectors-clusters), p.Data[1].NumSector)

			// Most of the partition is padding, so it should be tiny,
			// whereas encrypted it would be most of the disc
			assert.Less(t, len(b), len(disc)/8, "partition data not stored efficiently")
		})
	}
}

func TestCompressWiiBadKeyIndex(t *testing.T) {
	t.Parallel()

	err := Compress(nil, bytes.NewReader(nil), 0, WithCommonKey(numCommonKeys, testCommonKey))
	assert.ErrorIs(t, err, errBadCommonKeyIndex)
}
