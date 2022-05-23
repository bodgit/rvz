package rvz

import (
	"bytes"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
	"errors"
	"io"

	"github.com/bodgit/rvz/internal/packed"
)

const (
	compressed     uint32 = 1 << 31
	compressedMask        = compressed - 1

	gameCube = 1
	wii      = 2 //nolint:deadcode,varcheck
)

//nolint:maligned
type header struct {
	Magic             uint32
	Version           uint32
	VersionCompatible uint32
	DiscSize          uint32
	DiscHash          [sha1.Size]byte
	IsoFileSize       uint64
	RvzFileSize       uint64
	FileHeadHash      [sha1.Size]byte
}

func (h *header) discReader(ra io.ReaderAt) io.Reader {
	return io.NewSectionReader(ra, int64(binary.Size(h)), int64(h.DiscSize))
}

type disc struct {
	DiscType     uint32
	Compression  uint32
	ComprLevel   int32
	ChunkSize    uint32
	Header       [0x80]byte
	NumPart      uint32
	PartSize     uint32
	PartOff      uint64
	PartHash     [sha1.Size]byte
	NumRawData   uint32
	RawDataOff   uint64
	RawDataSize  uint32
	NumGroup     uint32
	GroupOff     uint64
	GroupSize    uint32
	ComprDataLen byte
	ComprData    [7]byte
}

func (d *disc) rawReader(ra io.ReaderAt) io.Reader {
	return io.NewSectionReader(ra, int64(d.RawDataOff), int64(d.RawDataSize))
}

func (d *disc) groupReader(ra io.ReaderAt) io.Reader {
	return io.NewSectionReader(ra, int64(d.GroupOff), int64(d.GroupSize))
}

type raw struct {
	RawDataOff  uint64
	RawDataSize uint64
	GroupIndex  uint32
	NumGroups   uint32
}

type group struct {
	Offset     uint32
	Size       uint32
	PackedSize uint32
}

func (g *group) offset() int64 {
	return int64(g.Offset << 2)
}

func (g *group) compressed() bool {
	return g.Size&compressed == compressed
}

func (g *group) size() int64 {
	return int64(g.Size & compressedMask)
}

type reader struct {
	ra io.ReaderAt

	header header
	disc   disc
	raw    []raw
	group  []group

	i      int
	gr     io.ReadCloser
	offset int64
}

func (r *reader) decompressor(reader io.Reader) (io.ReadCloser, error) {
	dcomp := decompressor(r.disc.Compression)
	if dcomp == nil {
		return nil, errors.New("rvz: unsupported algorithm")
	}

	return dcomp(r.disc.ComprData[0:r.disc.ComprDataLen], reader)
}

func (r *reader) groupReader(g int) (rc io.ReadCloser, err error) {
	group := r.group[g]
	if group.compressed() {
		rc, err = r.decompressor(io.NewSectionReader(r.ra, group.offset(), group.size()))
		if err != nil {
			return nil, err
		}
	} else {
		if group.size() == 0 {
			panic("rvz: all zeroes")
		}
		rc = io.NopCloser(io.NewSectionReader(r.ra, group.offset(), group.size()))
	}

	if group.PackedSize != 0 {
		rc, err = packed.NewReadCloser(rc, r.offset)
		if err != nil {
			return nil, err
		}
	}

	return
}

func (r *reader) Read(p []byte) (n int, err error) {
	n, err = r.gr.Read(p)
	r.offset += int64(n)

	if err != nil {
		if !errors.Is(err, io.EOF) {
			return
		}

		if err = r.gr.Close(); err != nil {
			return
		}

		r.i++

		if r.i == len(r.group) {
			return n, io.EOF
		}

		if r.gr, err = r.groupReader(r.i); err != nil {
			return
		}
	}

	return
}

func (r *reader) readRaw() error {
	cr, err := r.decompressor(r.disc.rawReader(r.ra))
	if err != nil {
		return err
	}
	defer cr.Close()

	r.raw = make([]raw, r.disc.NumRawData)
	if err = binary.Read(cr, binary.BigEndian, &r.raw); err != nil {
		return err
	}

	return nil
}

func (r *reader) readGroup() error {
	cr, err := r.decompressor(r.disc.groupReader(r.ra))
	if err != nil {
		return err
	}
	defer cr.Close()

	r.group = make([]group, r.disc.NumGroup)
	if err = binary.Read(cr, binary.BigEndian, &r.group); err != nil {
		return err
	}

	return nil
}

// NewReader returns a new io.Reader that reads and decompresses from ra.
//nolint:cyclop
func NewReader(ra io.ReaderAt) (io.Reader, error) {
	r := new(reader)
	r.ra = ra

	h := sha1.New() //nolint:gosec

	size := int64(binary.Size(r.header)) - sha1.Size

	// Create a reader that can read the whole struct, but the SHA1 hash at the end is excluded
	mr := io.MultiReader(io.TeeReader(io.NewSectionReader(ra, 0, size), h), io.NewSectionReader(ra, size, sha1.Size))
	if err := binary.Read(mr, binary.BigEndian, &r.header); err != nil {
		return nil, err
	}

	if !bytes.Equal(r.header.FileHeadHash[:], h.Sum(nil)) {
		return nil, errors.New("rvz: header hash doesn't match")
	}

	h.Reset()

	if int(r.header.DiscSize) != binary.Size(r.disc) {
		return nil, errors.New("rvz: disc struct has wrong size")
	}

	if err := binary.Read(io.TeeReader(r.header.discReader(ra), h), binary.BigEndian, &r.disc); err != nil {
		return nil, err
	}

	if !bytes.Equal(r.header.DiscHash[:], h.Sum(nil)) {
		return nil, errors.New("rvz: disc hash doesn't match")
	}

	if r.disc.DiscType != gameCube {
		return nil, errors.New("rvz: TODO non-GameCube disc")
	}

	h.Reset()

	if r.disc.NumPart > 0 {
		return nil, errors.New("rvz: TODO partitions")
	}

	if !bytes.Equal(r.disc.PartHash[:], h.Sum(nil)) {
		return nil, errors.New("rvz: partition hash doesn't match")
	}

	var err error

	if err = r.readRaw(); err != nil {
		return nil, err
	}

	if err = r.readGroup(); err != nil {
		return nil, err
	}

	if r.gr, err = r.groupReader(r.i); err != nil {
		return nil, err
	}

	return r, nil
}
