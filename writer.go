package rvz

import (
	"bytes"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bodgit/plumbing"
	"github.com/bodgit/rvz/internal/fst"
	"github.com/bodgit/rvz/internal/packed"
	"github.com/bodgit/rvz/internal/util"
	"github.com/bodgit/rvz/internal/zstd"
)

const (
	// DefaultChunkSize is the chunk size used by Compress unless
	// WithChunkSize is given.
	DefaultChunkSize = ChunkSize128KiB

	// DefaultMethod is the compression method used by Compress unless
	// WithCompression is given, which matches Dolphin.
	DefaultMethod = MethodZstandard

	// DefaultLevel is the compression level used by Compress unless
	// WithCompression is given, which matches Dolphin.
	DefaultLevel = 5

	gameCubeMagicOffset        = 0x1c
	gameCubeMagic       uint32 = 0xc2339f3d
	wiiMagicOffset             = 0x18
	wiiMagic            uint32 = 0x5d1c9ea3
)

type options struct {
	chunkSize int
	method    uint32
	level     int
}

// An Option configures how Compress creates an RVZ image.
type Option func(*options)

// WithChunkSize sets the size of each chunk the disc image is split into,
// which must be one of the ChunkSize constants. Smaller chunks make random
// access faster but compress less well.
func WithChunkSize(n int) Option {
	return func(o *options) {
		o.chunkSize = n
	}
}

// WithCompression sets the compression method and level. Only MethodNone
// and MethodZstandard are supported, with levels from 1 to 22 for the
// latter. The level is ignored for MethodNone.
func WithCompression(method uint32, level int) Option {
	return func(o *options) {
		o.method, o.level = method, level
	}
}

func (o *options) validate() error {
	if !validChunkSize(o.chunkSize) {
		return errBadChunkSize
	}

	switch o.method {
	case MethodNone:
		o.level = 0
	case MethodZstandard:
		if o.level < zstd.MinLevel || o.level > zstd.MaxLevel {
			return errBadCompressionLevel
		}
	default:
		return errUnsupportedAlgorithm
	}

	return nil
}

// A compressFunc appends src compressed to dst.
type compressFunc func(dst, src []byte) []byte

// compressor returns the function used to compress each group and table,
// or nil when nothing is compressed, along with a function to release it.
func (o *options) compressor() (compressFunc, func() error, error) {
	if o.method != MethodZstandard {
		return nil, func() error { return nil }, nil
	}

	c, err := zstd.NewCompressor(o.level)
	if err != nil {
		return nil, nil, fmt.Errorf("rvz: %w", err)
	}

	return c.Compress, c.Close, nil
}

// A reuseKey identifies a chunk where every byte has the same value.
type reuseKey struct {
	size  int
	value byte
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

	// Where each file on a GameCube disc is, to help find padding
	files *fst.Files

	compress compressFunc
	packed   []byte
	buf      []byte

	// Groups that can be reused by later chunks with the same contents
	reuse map[reuseKey]group

	written int64
}

// Compress converts the GameCube or Wii disc image read from ra, which is
// size bytes long, into an RVZ image written to w. The RVZ image can be read
// back with NewReader to give an identical disc image.
func Compress(w io.WriteSeeker, ra io.ReaderAt, size int64, opts ...Option) error {
	cw := &writer{
		w:     w,
		ra:    ra,
		size:  size,
		reuse: make(map[reuseKey]group),
		opts: options{
			chunkSize: DefaultChunkSize,
			method:    DefaultMethod,
			level:     DefaultLevel,
		},
	}

	for _, opt := range opts {
		opt(&cw.opts)
	}

	if err := cw.opts.validate(); err != nil {
		return err
	}

	compress, closeFunc, err := cw.opts.compressor()
	if err != nil {
		return err
	}

	cw.compress = compress

	if err := cw.convert(); err != nil {
		_ = closeFunc()

		return err
	}

	return closeFunc()
}

func (cw *writer) convert() error {
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

		// The file system only makes finding padding more effective, so
		// carry on without it if it can't be read
		cw.files, _ = fst.Read(cw.ra, 0)
	default:
		return errInvalidDiscType
	}

	cw.disc.Compression = cw.opts.method
	cw.disc.ComprLevel = int32(cw.opts.level)     //nolint:gosec // validated by options
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
// is rounded up to a whole sector. As Dolphin does, a compressed group table
// is assumed to be at most 9/16 of its original size, and some room is
// allowed for the compression overhead of the raw data table.
func (cw *writer) tablesSize() int64 {
	groups := int64(len(cw.group) * binary.Size(group{}))
	if cw.compress != nil {
		groups = groups * 9 / 16
	}

	n := int64(binary.Size(cw.header)) + int64(binary.Size(cw.disc)) +
		int64(len(cw.raw)*binary.Size(raw{})) + 0x100 + groups

	return (n + util.SectorSize - 1) / util.SectorSize * util.SectorSize
}

// writeRaw stores each group of a raw data area.
func (cw *writer) writeRaw(x *raw) error {
	start := x.offset() - x.offset()%util.SectorSize
	buf := make([]byte, cw.opts.chunkSize)

	for i := range int(x.NumGroup) {
		offset := start + int64(i)*int64(cw.opts.chunkSize)
		b := buf[:min(int64(cw.opts.chunkSize), x.end()-offset)]

		if _, err := cw.ra.ReadAt(b, offset); err != nil {
			return fmt.Errorf("rvz: reading disc image: %w", err)
		}

		if err := cw.writeGroup(int(x.GroupIndex)+i, offset, b); err != nil {
			return err
		}
	}

	return nil
}

// writeGroup stores a chunk, which starts offset bytes into the disc, as
// group g. A chunk of zeroes is stored as an empty group, and a chunk where
// every byte has the same value reuses an earlier group with the same
// contents if there is one.
func (cw *writer) writeGroup(g int, offset int64, b []byte) error {
	if len(b) == 0 || !bytes.Equal(b[1:], b[:len(b)-1]) {
		return cw.storeGroup(g, offset, b)
	}

	// The offset of an empty group isn't used
	if b[0] == 0 {
		cw.group[g] = group{}

		return nil
	}

	key := reuseKey{size: len(b), value: b[0]}

	if e, ok := cw.reuse[key]; ok {
		cw.group[g] = e

		return nil
	}

	if err := cw.storeGroup(g, offset, b); err != nil {
		return err
	}

	// As every byte is the same the chunk can't contain padding, so it
	// doesn't depend on its offset and is safe to reuse
	cw.reuse[key] = cw.group[g]

	return nil
}

// storeGroup writes the data for group g, with any padding replaced by
// seeds and then compressed if that makes it smaller, recording where it is,
// and pads it to the next 4 byte boundary.
func (cw *writer) storeGroup(g int, offset int64, b []byte) error {
	var packedSize uint32

	if p, ok := packed.Pack(cw.packed[:0], b, offset, cw.compress != nil, cw.files); ok {
		cw.packed = p
		b = p
		packedSize = uint32(len(p)) //nolint:gosec // at most a little over 2 MiB
	}

	size := uint32(len(b)) //nolint:gosec // at most a little over 2 MiB

	if cw.compress != nil {
		cw.buf = cw.compress(cw.buf[:0], b)

		if len(cw.buf) < len(b) {
			b = cw.buf
			size = uint32(len(b)) | compressed //nolint:gosec // smaller than the chunk
		}
	}

	cw.group[g] = group{
		Offset:     uint32(cw.written >> 2), //nolint:gosec // checked below
		Size:       size,
		PackedSize: packedSize,
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

	// The tables are always compressed, even if that makes them larger
	if cw.compress != nil {
		r, g := cw.compress(nil, raws.Bytes()), cw.compress(nil, groups.Bytes())

		raws.Reset()
		raws.Write(r)
		groups.Reset()
		groups.Write(g)
	}

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
