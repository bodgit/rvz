package rvz

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec
	"fmt"
	"io"

	"github.com/bodgit/rvz/internal/util"
)

const (
	subGroup         = 8
	clusters         = subGroup * subGroup // 8 groups of 8 subgroups
	blocksPerCluster = 31

	h0Size    = blocksPerCluster * sha1.Size
	h0Padding = 0x14
	h1Size    = subGroup * sha1.Size
	h1Padding = 0x20
	h2Size    = h1Size
	h2Padding = h1Padding
	hashSize  = h0Size + h0Padding + h1Size + h1Padding + h2Size + h2Padding

	h1Offset = h0Size + h0Padding
	h2Offset = h1Offset + h1Size + h1Padding

	blockSize = (util.SectorSize - hashSize) / blocksPerCluster

	ivOffset = 0x03d0

	groupSize = util.SectorSize * clusters // 2 MiB
)

// A partReader rebuilds the encrypted partition data. Each 2 MiB block is
// rebuilt independently so they can be prefetched in parallel.
type partReader struct {
	p, d int
	r    *reader
}

func (pr *partReader) area() partData {
	return pr.r.part[pr.p].Data[pr.d]
}

// rebuild reconstructs the i-th 2 MiB block of the partition into buf,
// returning how much of it is used.
func (pr *partReader) rebuild(i int, buf []byte) (int, error) {
	block, err := aes.NewCipher(pr.r.part[pr.p].Key[:])
	if err != nil {
		return 0, fmt.Errorf("rvz: %w", err)
	}

	first := i * clusters
	sectors := min(clusters, int(pr.area().NumSector)-first)

	exceptions, err := pr.readData(first, sectors, buf)
	if err != nil {
		return 0, err
	}

	writeHashes(buf)

	if err := applyExceptions(buf, exceptions, pr.r.disc.sectorsPerChunk()); err != nil {
		return 0, err
	}

	e := newSectorEncrypter(block)

	for s := range sectors {
		e.encrypt(buf[s*util.SectorSize : (s+1)*util.SectorSize])
	}

	return sectors * util.SectorSize, nil
}

// readData reads the data area of each sector in the block starting at the
// first sector into buf, zeroing any sectors beyond the end of the partition.
// It returns the hash exceptions for each chunk.
func (pr *partReader) readData(first, sectors int, buf []byte) ([][]except, error) {
	spc := pr.r.disc.sectorsPerChunk()
	exceptions := make([][]except, clusters/spc)

	for c := range exceptions {
		ss := c * spc
		n := max(min(spc, sectors-ss), 0)

		if n > 0 {
			var err error

			if exceptions[c], err = pr.readChunk(first+ss, n, buf[ss*util.SectorSize:]); err != nil {
				return nil, err
			}
		}

		// The hashes still cover sectors beyond the end
		for s := ss + n; s < ss+spc; s++ {
			clear(buf[s*util.SectorSize+hashSize : (s+1)*util.SectorSize])
		}
	}

	return exceptions, nil
}

// readChunk reads the data area of n sectors from the group holding the
// sector into buf, returning the hash exceptions for the group.
func (pr *partReader) readChunk(sector, n int, buf []byte) ([]except, error) {
	g := pr.sectorToGroup(sector)

	rc, exceptions, err := pr.r.groupReader(g, pr.groupOffset(g), true)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = rc.Close()
	}()

	for s := range n {
		if _, err := io.ReadFull(rc, buf[s*util.SectorSize+hashSize:(s+1)*util.SectorSize]); err != nil {
			return nil, fmt.Errorf("rvz: reading partition data: %w", err)
		}
	}

	return exceptions, nil
}

func (pr *partReader) groupOffset(g int) int64 {
	return (int64(g) - int64(pr.area().GroupIndex)) * pr.r.disc.chunkSize(true)
}

func (pr *partReader) sectorToGroup(sector int) int {
	return int(pr.area().GroupIndex) + sector/pr.r.disc.sectorsPerChunk()
}

// writeHashes calculates the H0, H1 and H2 hashes for each sector in the
// block, writing them into the hash area at the start of each sector.
func writeHashes(buf []byte) {
	sector := func(s int) []byte {
		return buf[s*util.SectorSize : (s+1)*util.SectorSize]
	}

	// The H0 hashes are of each 1 KiB block of a sector's own data
	for s := range clusters {
		b := sector(s)
		clear(b[:hashSize])

		for i := range blocksPerCluster {
			sum := sha1.Sum(b[hashSize+i*blockSize : hashSize+(i+1)*blockSize]) //nolint:gosec
			copy(b[i*sha1.Size:], sum[:])
		}
	}

	// The H1 hashes are of the H0 hashes of each sector in the subgroup
	// and are the same for every sector in it
	for g := range subGroup {
		h1 := sector(g * subGroup)[h1Offset : h1Offset+h1Size]

		for i := range subGroup {
			sum := sha1.Sum(sector(g*subGroup + i)[:h0Size]) //nolint:gosec
			copy(h1[i*sha1.Size:], sum[:])
		}

		for i := 1; i < subGroup; i++ {
			copy(sector(g*subGroup + i)[h1Offset:], h1)
		}
	}

	// The H2 hashes are of the H1 hashes of each subgroup and are the
	// same for every sector in the block
	h2 := sector(0)[h2Offset : h2Offset+h2Size]

	for g := range subGroup {
		sum := sha1.Sum(sector(g * subGroup)[h1Offset : h1Offset+h1Size]) //nolint:gosec
		copy(h2[g*sha1.Size:], sum[:])
	}

	for s := 1; s < clusters; s++ {
		copy(sector(s)[h2Offset:], h2)
	}
}

// applyExceptions replaces any recalculated hashes that didn't match the
// original disc. Exception offsets are relative to the hashes of the first
// sector in each chunk.
func applyExceptions(buf []byte, exceptions [][]except, sectorsPerChunk int) error {
	for c, exceptions := range exceptions {
		base := c * sectorsPerChunk * hashSize

		for _, e := range exceptions {
			offset := base + int(e.Offset)
			sector, offset := offset/hashSize, offset%hashSize

			if sector >= clusters || offset+sha1.Size > hashSize {
				return errBadExceptionOffset
			}

			copy(buf[sector*util.SectorSize+offset:], e.Hash[:])
		}
	}

	return nil
}

//nolint:gochecknoglobals
var iv = make([]byte, aes.BlockSize) // 16 x 0x00

// A sectorEncrypter encrypts sectors, reusing the same CBC encrypter for
// each IV where possible.
type sectorEncrypter struct {
	block cipher.Block
	cbc   cipher.BlockMode
}

func newSectorEncrypter(block cipher.Block) *sectorEncrypter {
	return &sectorEncrypter{block: block}
}

func (se *sectorEncrypter) mode(iv []byte) cipher.BlockMode {
	if s, ok := se.cbc.(interface{ SetIV(iv []byte) }); ok {
		s.SetIV(iv)

		return se.cbc
	}

	se.cbc = cipher.NewCBCEncrypter(se.block, iv)

	return se.cbc
}

// encrypt encrypts a sector in place.
func (se *sectorEncrypter) encrypt(b []byte) {
	// The disc format encrypts the hash block with an all-zero IV, and the
	// data with an IV taken from the encrypted hash block
	se.mode(iv).CryptBlocks(b[:hashSize], b[:hashSize]) //nolint:gosec // required by the disc format
	se.mode(b[ivOffset:ivOffset+aes.BlockSize]).CryptBlocks(b[hashSize:], b[hashSize:])
}

func newPartReader(r *reader, p, d int) io.Reader {
	pr := &partReader{
		p: p,
		d: d,
		r: r,
	}

	blocks := (int(pr.area().NumSector) + clusters - 1) / clusters

	return newPrefetcher(blocks, pr.rebuild)
}
