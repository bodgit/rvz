package rvz

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"github.com/bodgit/rvz/internal/fst"
	"github.com/bodgit/rvz/internal/packed"
	"github.com/bodgit/rvz/internal/util"
)

// The Wii common keys, numbered as in the ticket of each partition.
const (
	CommonKeyRetail = iota
	CommonKeyKorean
	CommonKeyVWii

	numCommonKeys
)

const (
	wiiHashesOffset     = 0x60 // zero if the disc has hashes
	wiiEncryptionOffset = 0x61 // zero if the disc is encrypted

	partitionTableOffset = 0x40000
	partitionGroups      = 4

	partitionDataInfo = 0x2b8 // data offset and size, both shifted

	ticketSize           = 0x2a4
	ticketTitleKey       = 0x1bf
	ticketTitleID        = 0x1dc
	ticketCommonKeyIndex = 0x1f1

	sectorDataSize = util.SectorSize - hashSize // 0x7c00
)

// partitionSignature is the signature type at the start of a partition's
// ticket, which Dolphin uses to tell a partition from garbage.
const partitionSignature uint32 = 0x10001

// WithCommonKey supplies one of the Wii common keys, which are needed to
// decrypt the partitions of a Wii disc so they can be compressed. A partition
// whose key isn't supplied, or is wrong, is stored as it is, encrypted,
// which is valid but barely compresses.
func WithCommonKey(index int, key [aes.BlockSize]byte) Option {
	return func(o *options) {
		if o.commonKeys == nil {
			o.commonKeys = make(map[int][aes.BlockSize]byte)
		}

		o.commonKeys[index] = key
	}
}

// A wiiPartition holds what is needed to compress a partition.
type wiiPartition struct {
	part  part
	block cipher.Block

	// Where each file in the partition is, to help find padding
	files *fst.Files
}

// partitionOffsets returns the offset of each partition in the partition
// table, in order.
func (cw *writer) partitionOffsets() []int64 {
	var offsets []int64

	for g := range int64(partitionGroups) {
		var b [8]byte
		if _, err := cw.ra.ReadAt(b[:], partitionTableOffset+g*8); err != nil {
			continue
		}

		n := int64(binary.BigEndian.Uint32(b[0:]))
		table := int64(binary.BigEndian.Uint32(b[4:])) << 2

		// Each entry is 8 bytes, so a table larger than the disc is
		// garbage
		if n*8 > cw.size {
			continue
		}

		entries := make([]byte, n*8)
		if _, err := cw.ra.ReadAt(entries, table); err != nil {
			continue
		}

		for e := range slices.Chunk(entries, 8) {
			offsets = append(offsets, int64(binary.BigEndian.Uint32(e))<<2)
		}
	}

	slices.Sort(offsets)

	return offsets
}

// readPartition checks the partition at offset can be stored as partition
// data and returns its offset and size along with what is needed to compress
// it. As with Dolphin, anything odd about the partition means it is stored
// as raw data instead, as is a partition whose key isn't known.
func (cw *writer) readPartition(offset int64) (*wiiPartition, int64, int64, bool) {
	var b [8]byte

	if _, err := cw.ra.ReadAt(b[:4], offset); err != nil || binary.BigEndian.Uint32(b[:]) != partitionSignature {
		return nil, 0, 0, false
	}

	if _, err := cw.ra.ReadAt(b[:], offset+partitionDataInfo); err != nil {
		return nil, 0, 0, false
	}

	dataOffset := int64(binary.BigEndian.Uint32(b[0:])) << 2
	dataSize := int64(binary.BigEndian.Uint32(b[4:])) << 2
	dataStart := offset + dataOffset

	if dataStart%util.SectorSize != 0 || dataSize < util.SectorSize || dataStart >= cw.size {
		return nil, 0, 0, false
	}

	dataSize = min(dataSize, cw.size-dataStart)

	block, key, ok := cw.titleKey(offset)
	if !ok || !checkKey(cw.ra, block, dataStart) {
		return nil, 0, 0, false
	}

	pr := &partitionReader{
		ra:      cw.ra,
		block:   block,
		start:   dataStart,
		sectors: dataSize / util.SectorSize,
	}

	files, err := fst.Read(pr, 2)
	if err != nil {
		return nil, 0, 0, false
	}

	return &wiiPartition{
		part:  part{Key: key},
		block: block,
		files: files,
	}, dataOffset, dataSize, true
}

// titleKey decrypts the title key of the partition at offset using the
// common key its ticket names, if it was supplied.
func (cw *writer) titleKey(offset int64) (cipher.Block, [aes.BlockSize]byte, bool) {
	var (
		ticket [ticketSize]byte
		key    [aes.BlockSize]byte
	)

	if _, err := cw.ra.ReadAt(ticket[:], offset); err != nil {
		return nil, key, false
	}

	commonKey, ok := cw.opts.commonKeys[int(ticket[ticketCommonKeyIndex])]
	if !ok {
		return nil, key, false
	}

	common, err := aes.NewCipher(commonKey[:])
	if err != nil {
		return nil, key, false
	}

	// The IV is the title ID followed by zeroes
	var iv [aes.BlockSize]byte

	copy(iv[:], ticket[ticketTitleID:ticketTitleID+8])
	cipher.NewCBCDecrypter(common, iv[:]).CryptBlocks(key[:], ticket[ticketTitleKey:ticketTitleKey+aes.BlockSize])

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, key, false
	}

	return block, key, true
}

// checkKey checks the first sector of the partition data decrypts to data
// matching its own first hash, which catches a wrong common key.
func checkKey(ra io.ReaderAt, block cipher.Block, dataStart int64) bool {
	sector := make([]byte, util.SectorSize)
	if _, err := ra.ReadAt(sector, dataStart); err != nil {
		return false
	}

	var hashes [hashSize]byte

	data := make([]byte, sectorDataSize)
	decryptSector(block, sector, hashes[:], data)

	sum := sha1.Sum(data[:blockSize]) //nolint:gosec

	return bytes.Equal(sum[:], hashes[:sha1.Size])
}

// decryptSector decrypts an encrypted sector into its hashes and data.
func decryptSector(block cipher.Block, sector, hashes, data []byte) {
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(hashes, sector[:hashSize])
	cipher.NewCBCDecrypter(block, sector[ivOffset:ivOffset+aes.BlockSize]).CryptBlocks(data, sector[hashSize:])
}

// partitionReader reads the decrypted data of a partition, as the file
// system sees it, with the hashes removed.
type partitionReader struct {
	ra      io.ReaderAt
	block   cipher.Block
	start   int64 // where the partition data starts on the disc
	sectors int64
}

func (pr *partitionReader) ReadAt(p []byte, off int64) (int, error) {
	var (
		n      int
		sector = make([]byte, util.SectorSize)
		hashes [hashSize]byte
		data   = make([]byte, sectorDataSize)
	)

	for n < len(p) {
		s, in := (off+int64(n))/sectorDataSize, (off+int64(n))%sectorDataSize
		if s >= pr.sectors {
			return n, io.EOF
		}

		if _, err := pr.ra.ReadAt(sector, pr.start+s*util.SectorSize); err != nil {
			return n, err //nolint:wrapcheck // returned as is from the disc
		}

		decryptSector(pr.block, sector, hashes[:], data)

		n += copy(p[n:], data[in:])
	}

	return n, nil
}

// rawOffset converts an offset in the partition data, as the file system
// sees it, to where it is on the disc.
func rawOffset(dataStart, offset int64) int64 {
	return dataStart + offset/sectorDataSize*util.SectorSize + hashSize + offset%sectorDataSize
}

// addPartition stores the partition at offset as partition data, split as
// Dolphin does into the part up to the end of the file system table, which
// is rounded up to 2 MiB, and the rest.
func (cw *writer) addPartition(p *wiiPartition, offset, dataOffset, dataSize int64) int64 {
	dataStart := offset + dataOffset
	dataEnd := dataStart + dataSize

	split := min(dataEnd, dataStart+alignUp(rawOffset(dataStart, p.files.TableEnd())-dataStart, groupSize))

	p.part.Data[0] = cw.addPartData(len(cw.wii), 0, dataStart, split-dataStart)
	p.part.Data[1] = cw.addPartData(len(cw.wii), 1, split, dataEnd-split)

	cw.wii = append(cw.wii, p)

	// The data areas only cover whole sectors, so the end may have been
	// rounded down
	return int64(p.part.Data[1].FirstSector+p.part.Data[1].NumSector) * util.SectorSize
}

// addPartData adds one of the two data areas of a partition.
func (cw *writer) addPartData(p, d int, offset, size int64) partData {
	sectors := size / util.SectorSize
	groups := ceilDiv(uint64(sectors)*util.SectorSize, uint64(cw.opts.chunkSize)) //nolint:gosec

	// All of these are bounded by the size of the disc
	pd := partData{
		FirstSector: uint32(offset / util.SectorSize), //nolint:gosec
		NumSector:   uint32(sectors),                  //nolint:gosec
		GroupIndex:  uint32(cw.groups()),              //nolint:gosec
		NumGroup:    uint32(groups),                   //nolint:gosec
	}

	cw.areas = append(cw.areas, area{raw: -1, p: p, d: d, numGroup: int(groups)}) //nolint:gosec

	return pd
}

// hashAreas are the parts of the hash area of a sector that are compared
// with the recalculated hashes, as Dolphin does, including the padding.
//
//nolint:gochecknoglobals
var hashAreas = [][2]int{
	{0, h0Size},
	{h0Size, h0Padding},
	{h1Offset, h1Size},
	{h1Offset + h1Size, h1Padding},
	{h2Offset, h2Size},
	{h2Offset + h2Size, h2Padding},
}

// writePartData stores data area d of partition p. Each 2 MiB block is
// decrypted and its hashes recalculated, with any that don't match the
// originals stored as hash exceptions in the group for the chunk.
func (cw *writer) writePartData(p, d int) error {
	wp := cw.wii[p]
	pd := wp.part.Data[d]
	spc := cw.opts.chunkSize / util.SectorSize // sectors per chunk

	var (
		enc    = make([]byte, groupSize)
		buf    = make([]byte, groupSize) // decrypted, hashes recalculated
		hashes = make([]byte, clusters*hashSize)
		data   = make([]byte, clusters*sectorDataSize)
	)

	for first := 0; first < int(pd.NumSector); first += clusters {
		sectors := min(clusters, int(pd.NumSector)-first)
		sector := int64(pd.FirstSector) + int64(first)

		if _, err := cw.ra.ReadAt(enc[:sectors*util.SectorSize], sector*util.SectorSize); err != nil {
			return fmt.Errorf("rvz: reading disc image: %w", err)
		}

		// Sectors beyond the end are zeroes when recalculating hashes
		clear(buf)

		for s := range sectors {
			decryptSector(wp.block, enc[s*util.SectorSize:(s+1)*util.SectorSize],
				hashes[s*hashSize:(s+1)*hashSize], buf[s*util.SectorSize+hashSize:(s+1)*util.SectorSize])
			copy(data[s*sectorDataSize:], buf[s*util.SectorSize+hashSize:(s+1)*util.SectorSize])
		}

		writeHashes(buf)

		// Padding is generated relative to the start of the partition
		// data, not this data area
		offset := (sector - int64(wp.part.Data[0].FirstSector)) * sectorDataSize
		b := data[:sectors*sectorDataSize]
		junk := packed.Find(b, offset, cw.compress != nil, wp.files)

		for c := 0; c*spc < sectors; c++ {
			start, end := c*spc, min((c+1)*spc, sectors)

			exceptions := hashExceptions(buf, hashes, start, end)

			var packedSize uint32

			chunk := b[start*sectorDataSize : end*sectorDataSize]
			if pb, ok := junk.Pack(cw.packed[:0], b, start*sectorDataSize, end*sectorDataSize); ok {
				cw.packed = pb
				chunk = pb
				packedSize = uint32(len(pb)) //nolint:gosec // a little over 2 MiB
			}

			g := int(pd.GroupIndex) + (first+start)/spc
			if err := cw.storeGroup(g, exceptions, chunk, packedSize); err != nil {
				return err
			}
		}
	}

	return nil
}

// hashExceptions returns the hash exception list for the sectors from start
// to end, comparing the recalculated hashes in buf with the original ones.
// Offsets are relative to the hashes of the first sector.
func hashExceptions(buf, hashes []byte, start, end int) []byte {
	b := make([]byte, 2, 2+(end-start)*hashSize)

	var n uint16

	for s := start; s < end; s++ {
		want := hashes[s*hashSize : (s+1)*hashSize]
		got := buf[s*util.SectorSize : s*util.SectorSize+hashSize]

		for _, a := range hashAreas {
			// Areas that aren't a whole number of hashes overlap at the
			// end, as with Dolphin
			for l := 0; l < a[1]; l += sha1.Size {
				o := a[0] + min(l, a[1]-sha1.Size)

				if !bytes.Equal(want[o:o+sha1.Size], got[o:o+sha1.Size]) {
					b = binary.BigEndian.AppendUint16(b, uint16((s-start)*hashSize+o)) //nolint:gosec // within a chunk
					b = append(b, want[o:o+sha1.Size]...)
					n++
				}
			}
		}
	}

	binary.BigEndian.PutUint16(b, n)

	return b
}
