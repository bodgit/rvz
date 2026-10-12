package rvz

import (
	"bytes"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bodgit/plumbing"
	"github.com/bodgit/rvz/internal/util"
)

const (
	// DefaultChunkSize is the chunk size used by Compress unless
	// WithChunkSize is given.
	DefaultChunkSize = 128 << 10 // 128 KiB

	gameCubeMagicOffset        = 0x1c
	gameCubeMagic       uint32 = 0xc2339f3d
	wiiMagicOffset             = 0x18
	wiiMagic            uint32 = 0x5d1c9ea3
)

type options struct {
	chunkSize int
}

// An Option configures how Compress creates an RVZ image.
type Option func(*options)

// WithChunkSize sets the size of each chunk the disc image is split into.
// It must be a power of two between 32 KiB and 2 MiB. Smaller chunks make
// random access faster but compress less well.
func WithChunkSize(n int) Option {
	return func(o *options) {
		o.chunkSize = n
	}
}

func (o *options) validate() error {
	if o.chunkSize < util.SectorSize || o.chunkSize > groupSize || o.chunkSize&(o.chunkSize-1) != 0 {
		return errBadChunkSize
	}

	return nil
}

// A writer holds the state of a single conversion.
type writer struct {
	w    io.WriteSeeker
	ra   io.ReaderAt
	size int64
	opts options

	header header
	disc   disc
	raw    []raw
	group  []group

	written int64
}

// Compress converts the GameCube or Wii disc image read from ra, which is
// size bytes long, into an RVZ image written to w. The RVZ image can be read
// back with NewReader to give an identical disc image.
func Compress(w io.WriteSeeker, ra io.ReaderAt, size int64, opts ...Option) error {
	cw := &writer{
		w:    w,
		ra:   ra,
		size: size,
		opts: options{
			chunkSize: DefaultChunkSize,
		},
	}

	for _, opt := range opts {
		opt(&cw.opts)
	}

	if err := cw.opts.validate(); err != nil {
		return err
	}

	return cw.compress()
}

func (cw *writer) compress() error {
	if err := cw.setUpDisc(); err != nil {
		return err
	}

	cw.setUpEntries()

	// Reserve space for the headers and tables at the start of the
	// file. They are written last, once the group table is known
	reserved := cw.tablesSize()
	if err := cw.writeZeroes(reserved); err != nil {
		return err
	}

	for i := range cw.raw {
		if err := cw.writeRaw(&cw.raw[i]); err != nil {
			return err
		}
	}

	return cw.writeTables(reserved)
}

// setUpDisc checks the disc image and fills in the parts of the disc header
// that don't depend on the layout.
func (cw *writer) setUpDisc() error {
	if cw.size < int64(len(cw.disc.Header)) || cw.size > maxIsoFileSize {
		return errBadDiscSize
	}

	if _, err := cw.ra.ReadAt(cw.disc.Header[:], 0); err != nil {
		return fmt.Errorf("rvz: reading disc header: %w", err)
	}

	switch {
	case binary.BigEndian.Uint32(cw.disc.Header[wiiMagicOffset:]) == wiiMagic:
		cw.disc.DiscType = wii
	case binary.BigEndian.Uint32(cw.disc.Header[gameCubeMagicOffset:]) == gameCubeMagic:
		cw.disc.DiscType = gameCube
	default:
		return errInvalidDiscType
	}

	cw.disc.ChunkSize = uint32(cw.opts.chunkSize) //nolint:gosec // validated by options

	return nil
}

// setUpEntries lays out the disc. For now everything is stored as a single
// raw data area.
func (cw *writer) setUpEntries() {
	cw.addRaw(0, cw.size)

	cw.group = make([]group, cw.groups())
}

// addRaw adds a raw data area. The first 0x80 bytes of the disc are stored
// in the disc header so are excluded, although like every raw data area the
// groups still start on a sector boundary.
func (cw *writer) addRaw(offset, size int64) {
	skip := min(max(int64(len(cw.disc.Header))-offset, 0), size)

	offset += skip
	size -= skip

	if size == 0 {
		return
	}

	aligned := offset - offset%util.SectorSize

	cw.raw = append(cw.raw, raw{
		RawDataOff:  uint64(offset),                                                          //nolint:gosec
		RawDataSize: uint64(size),                                                            //nolint:gosec
		GroupIndex:  uint32(cw.groups()),                                                     //nolint:gosec
		NumGroup:    uint32(ceilDiv(uint64(offset+size-aligned), uint64(cw.opts.chunkSize))), //nolint:gosec
	})
}

// groups returns the number of groups used so far.
func (cw *writer) groups() int {
	n := 0
	for _, x := range cw.raw {
		n += int(x.NumGroup)
	}

	return n
}

// tablesSize returns the space reserved for the headers and tables, which
// is rounded up to a whole sector as Dolphin does.
func (cw *writer) tablesSize() int64 {
	n := int64(binary.Size(cw.header)) + int64(binary.Size(cw.disc)) +
		int64(len(cw.raw)*binary.Size(raw{})) + int64(len(cw.group)*binary.Size(group{}))

	return (n + util.SectorSize - 1) / util.SectorSize * util.SectorSize
}

// writeRaw stores each group of a raw data area uncompressed.
func (cw *writer) writeRaw(x *raw) error {
	start := x.offset() - x.offset()%util.SectorSize
	buf := make([]byte, cw.opts.chunkSize)

	for i := range int(x.NumGroup) {
		offset := start + int64(i)*int64(cw.opts.chunkSize)
		b := buf[:min(int64(cw.opts.chunkSize), x.end()-offset)]

		if _, err := cw.ra.ReadAt(b, offset); err != nil {
			return fmt.Errorf("rvz: reading disc image: %w", err)
		}

		if err := cw.writeGroup(int(x.GroupIndex)+i, b); err != nil {
			return err
		}
	}

	return nil
}

// writeGroup writes the data for a group, recording where it is, and pads it
// to the next 4 byte boundary.
func (cw *writer) writeGroup(g int, b []byte) error {
	cw.group[g] = group{
		Offset: uint32(cw.written >> 2), //nolint:gosec // checked below
		Size:   uint32(len(b)),          //nolint:gosec // at most 2 MiB
	}

	if cw.written>>2 > int64(^uint32(0)) {
		return errFileTooLarge
	}

	if err := cw.write(b); err != nil {
		return err
	}

	return cw.padTo4()
}

// writeTables writes the tables and headers into the space reserved at the
// start of the file, or at the end if they don't fit.
func (cw *writer) writeTables(reserved int64) error {
	var raws, groups bytes.Buffer

	_ = binary.Write(&raws, binary.BigEndian, cw.raw)
	_ = binary.Write(&groups, binary.BigEndian, cw.group)

	end := cw.written
	offset := int64(binary.Size(cw.header)) + int64(binary.Size(cw.disc))

	if offset+int64(raws.Len()+groups.Len())+8 > reserved {
		offset = end
	}

	if _, err := cw.w.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("rvz: %w", err)
	}

	cw.written = offset

	// There are no partitions yet, so the partition table is empty
	cw.disc.PartOff = uint64(cw.written) //nolint:gosec
	cw.disc.PartHash = sha1.Sum(nil)     //nolint:gosec

	cw.disc.NumRawData = uint32(len(cw.raw)) //nolint:gosec
	cw.disc.RawDataOff = uint64(cw.written)  //nolint:gosec
	cw.disc.RawDataSize = uint32(raws.Len()) //nolint:gosec

	if err := cw.writePadded(raws.Bytes()); err != nil {
		return err
	}

	cw.disc.NumGroup = uint32(len(cw.group)) //nolint:gosec
	cw.disc.GroupOff = uint64(cw.written)    //nolint:gosec
	cw.disc.GroupSize = uint32(groups.Len()) //nolint:gosec

	if err := cw.writePadded(groups.Bytes()); err != nil {
		return err
	}

	return cw.writeHeaders(max(end, cw.written))
}

// writeHeaders writes the file and disc headers at the start of the file.
func (cw *writer) writeHeaders(fileSize int64) error {
	var discBuf, headerBuf bytes.Buffer

	_ = binary.Write(&discBuf, binary.BigEndian, &cw.disc)

	cw.header = header{
		Magic:             rvzMagic,
		Version:           rvzVersion,
		VersionCompatible: rvzVersionReadCompatible,
		DiscSize:          uint32(discBuf.Len()),     //nolint:gosec
		DiscHash:          sha1.Sum(discBuf.Bytes()), //nolint:gosec
		IsoFileSize:       uint64(cw.size),           //nolint:gosec
		RvzFileSize:       uint64(fileSize),          //nolint:gosec
	}

	_ = binary.Write(&headerBuf, binary.BigEndian, &cw.header)
	b := headerBuf.Bytes()
	hash := sha1.Sum(b[:len(b)-sha1.Size]) //nolint:gosec
	copy(b[len(b)-sha1.Size:], hash[:])

	if _, err := cw.w.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rvz: %w", err)
	}

	cw.written = 0

	if err := cw.write(b); err != nil {
		return err
	}

	return cw.write(discBuf.Bytes())
}

func (cw *writer) write(b []byte) error {
	n, err := cw.w.Write(b)
	cw.written += int64(n)

	if err != nil {
		return fmt.Errorf("rvz: writing: %w", err)
	}

	return nil
}

func (cw *writer) writePadded(b []byte) error {
	if err := cw.write(b); err != nil {
		return err
	}

	return cw.padTo4()
}

func (cw *writer) padTo4() error {
	return cw.writeZeroes((4 - cw.written%4) % 4)
}

func (cw *writer) writeZeroes(n int64) error {
	written, err := io.CopyN(cw.w, plumbing.DevZero(), n)
	cw.written += written

	if err != nil {
		return fmt.Errorf("rvz: writing: %w", err)
	}

	return nil
}
