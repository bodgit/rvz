package rvz

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"testing"

	"github.com/bodgit/rvz/internal/util"
	"github.com/stretchr/testify/assert"
)

const testSectors = 2

// testPartition returns a reader for a partition of testSectors sectors
// stored as uncompressed groups, with the exceptions for each group. The
// data in each group is filled with 0x11, 0x22, etc.
func testPartition(t *testing.T, chunkSize uint32, exceptions [][]except) *reader {
	t.Helper()

	r := &reader{
		disc: disc{
			ChunkSize: chunkSize,
			NumGroup:  uint32(len(exceptions)),
		},
		part: []part{
			{
				Key: [aes.BlockSize]byte{0x01, 0x02, 0x03, 0x04},
				Data: [2]partData{
					{
						NumSector: testSectors,
						NumGroup:  uint32(len(exceptions)),
					},
				},
			},
		},
	}

	sectorsPerGroup := min(r.disc.sectorsPerChunk(), testSectors)
	b := new(bytes.Buffer)

	for i, e := range exceptions {
		offset := b.Len()

		_ = binary.Write(b, binary.BigEndian, uint16(len(e)))
		_ = binary.Write(b, binary.BigEndian, e)

		for b.Len()%4 != 0 {
			_ = b.WriteByte(0)
		}

		b.Write(bytes.Repeat([]byte{byte(0x11 * (i + 1))}, sectorsPerGroup*(util.SectorSize-hashSize)))

		r.group = append(r.group, group{
			Offset: uint32(offset >> 2),
			Size:   uint32(b.Len() - offset),
		})
	}

	r.ra = bytes.NewReader(b.Bytes())

	return r
}

// decryptSector returns the decrypted hash and data areas of a sector.
func decryptSector(t *testing.T, key [aes.BlockSize]byte, sector []byte) ([]byte, []byte) {
	t.Helper()

	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}

	hashes := make([]byte, hashSize)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(hashes, sector[:hashSize])

	data := make([]byte, util.SectorSize-hashSize)
	cipher.NewCBCDecrypter(block, sector[ivOffset:ivOffset+aes.BlockSize]).CryptBlocks(data, sector[hashSize:])

	return hashes, data
}

//nolint:funlen
func TestHashExceptions(t *testing.T) {
	t.Parallel()

	hash := [20]byte{}
	for i := range hash {
		hash[i] = 0xee
	}

	tables := []struct {
		name       string
		chunkSize  uint32
		exceptions [][]except
		sector     int
		offset     int
		err        bool
	}{
		{
			name:      "no exceptions",
			chunkSize: util.SectorSize,
			exceptions: [][]except{
				nil,
				nil,
			},
			sector: -1,
		},
		{
			name:      "relative to chunk",
			chunkSize: util.SectorSize,
			exceptions: [][]except{
				nil,
				{{Offset: 0x14, Hash: hash}},
			},
			sector: 1,
			offset: 0x14,
		},
		{
			name:      "relative to 2 MiB",
			chunkSize: util.SectorSize << 6,
			exceptions: [][]except{
				{{Offset: hashSize + 0x14, Hash: hash}},
			},
			sector: 1,
			offset: 0x14,
		},
		{
			name:      "last hash",
			chunkSize: util.SectorSize,
			exceptions: [][]except{
				{{Offset: hashSize - 0x2c, Hash: hash}},
				nil,
			},
			sector: 0,
			offset: hashSize - 0x2c,
		},
		{
			name:      "offset straddles sectors",
			chunkSize: util.SectorSize,
			exceptions: [][]except{
				{{Offset: hashSize - 0x10, Hash: hash}},
				nil,
			},
			err: true,
		},
		{
			name:      "offset beyond 2 MiB",
			chunkSize: util.SectorSize,
			exceptions: [][]except{
				nil,
				{{Offset: (clusters - 1) * hashSize, Hash: hash}},
			},
			err: true,
		},
	}

	for _, table := range tables {
		table := table

		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			r := testPartition(t, table.chunkSize, table.exceptions)

			b, err := io.ReadAll(newPartReader(r, 0, 0))
			if table.err {
				assert.Error(t, err)

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			assert.Len(t, b, testSectors*util.SectorSize)

			for s := 0; s < testSectors; s++ {
				hashes, data := decryptSector(t, r.part[0].Key, b[s*util.SectorSize:(s+1)*util.SectorSize])

				g := s / r.disc.sectorsPerChunk()
				assert.Equal(t, len(data), bytes.Count(data, []byte{byte(0x11 * (g + 1))}), "sector %d data", s)

				// The H0 hashes are never all 0xee, so only the
				// exception can put it there
				applied := bytes.Equal(hashes[table.offset:table.offset+len(hash)], hash[:])
				assert.Equal(t, s == table.sector, applied, "sector %d exception", s)
			}
		})
	}
}
