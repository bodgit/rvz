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
	chunkSize  int
	method     uint32
	level      int
	commonKeys map[int][16]byte
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

	for index := range o.commonKeys {
		if index < 0 || index >= numCommonKeys {
			return errBadCommonKeyIndex
		}
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

// An area is either a raw data area or one of the data areas of a Wii
// partition, which are stored in the order they appear on the disc.
type area struct {
	raw      int // index of the raw data area, or -1 for a partition
	p, d     int // index of the partition and its data area
	numGroup int
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
	wii    []*wiiPartition
	group  []group
	areas  []area

	// Where each file on a GameCube disc is, to help find padding
	files *fst.Files

	compress compressFunc
	packed   []byte
	joined   []byte
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

	for _, a := range cw.areas {
		var err error

		if a.raw >= 0 {
			err = cw.writeRaw(&cw.raw[a.raw])
		} else {
			err = cw.writePartData(a.p, a.d)
		}

		if err != nil {
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

// setUpEntries lays out the disc. The partitions of a Wii disc are stored
// as partition data if they can be decrypted, and everything else is stored
// as raw data.
func (cw *writer) setUpEntries() {
	var last int64

	// A disc without hashes or encryption is stored as raw data
	if cw.disc.DiscType == wii && cw.disc.Header[wiiHashesOffset] == 0 && cw.disc.Header[wiiEncryptionOffset] == 0 {
		for _, offset := range cw.partitionOffsets() {
			// Skip overlapping partitions
			if offset < last {
				continue
			}

			p, dataOffset, dataSize, ok := cw.readPartition(offset)
			if !ok {
				continue
			}

			// The gap before the partition and its header are raw data
			cw.addRaw(last, offset-last)
			cw.addRaw(offset, dataOffset)

			last = cw.addPartition(p, offset, dataOffset, dataSize)
		}
	}

	cw.addRaw(last, cw.size-last)

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
	groups := int(ceilDiv(uint64(offset+size-aligned), uint64(cw.opts.chunkSize))) //nolint:gosec

	cw.raw = append(cw.raw, raw{
		RawDataOff:  uint64(offset),      //nolint:gosec
		RawDataSize: uint64(size),        //nolint:gosec
		GroupIndex:  uint32(cw.groups()), //nolint:gosec
		NumGroup:    uint32(groups),      //nolint:gosec
	})

	cw.areas = append(cw.areas, area{raw: len(cw.raw) - 1, numGroup: groups})
}

// groups returns the number of groups used so far.
func (cw *writer) groups() int {
	n := 0
	for _, a := range cw.areas {
		n += a.numGroup
	}

	return n
}

func alignUp(x, n int64) int64 {
	return (x + n - 1) / n * n
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

	n := int64(binary.Size(cw.header)) + int64(binary.Size(cw.disc)) + int64(len(cw.wii)*binary.Size(part{})) +
		int64(len(cw.raw)*binary.Size(raw{})) + 0x100 + groups

	return alignUp(n, util.SectorSize)
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
		return cw.storeRawGroup(g, offset, b)
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

	if err := cw.storeRawGroup(g, offset, b); err != nil {
		return err
	}

	// As every byte is the same the chunk can't contain padding, so it
	// doesn't depend on its offset and is safe to reuse
	cw.reuse[key] = cw.group[g]

	return nil
}

// storeRawGroup writes the data for raw data group g with any padding
// replaced by seeds.
func (cw *writer) storeRawGroup(g int, offset int64, b []byte) error {
	var packedSize uint32

	if p, ok := packed.Pack(cw.packed[:0], b, offset, cw.compress != nil, cw.files); ok {
		cw.packed = p
		b = p
		packedSize = uint32(len(p)) //nolint:gosec // at most a little over 2 MiB
	}

	return cw.storeGroup(g, nil, b, packedSize)
}

// storeGroup writes the data for group g, which is any hash exceptions
// followed by the data itself, compressed if that makes it smaller. It
// records where the group is and pads it to the next 4 byte boundary.
func (cw *writer) storeGroup(g int, exceptions, b []byte, packedSize uint32) error {
	// Uncompressed, the exceptions are padded so the data starts on a 4
	// byte boundary
	padding := int(alignUp(int64(len(exceptions)), 4)) - len(exceptions)
	parts := [][]byte{exceptions, make([]byte, padding), b}
	size := uint32(len(exceptions) + padding + len(b)) //nolint:gosec // a little over 2 MiB

	if cw.compress != nil {
		src := b
		if len(exceptions) > 0 {
			cw.joined = append(append(cw.joined[:0], exceptions...), b...)
			src = cw.joined
		}

		cw.buf = cw.compress(cw.buf[:0], src)

		if len(cw.buf) < int(size) {
			parts = [][]byte{cw.buf}
			size = uint32(len(cw.buf)) | compressed //nolint:gosec // smaller than the chunk
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

	for _, part := range parts {
		if err := cw.write(part); err != nil {
			return err
		}
	}

	return cw.padTo4()
}

// writeTables writes the tables and headers into the space reserved at the
// start of the file, or at the end if they don't fit.
func (cw *writer) writeTables(reserved int64) error {
	var parts, raws, groups bytes.Buffer

	for _, p := range cw.wii {
		_ = binary.Write(&parts, binary.BigEndian, &p.part)
	}

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

	if offset+int64(parts.Len()+raws.Len()+groups.Len())+8 > reserved {
		offset = end
	}

	if _, err := cw.w.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("rvz: %w", err)
	}

	cw.written = offset

	// The partition table is never compressed
	cw.disc.NumPart = uint32(len(cw.wii))          //nolint:gosec
	cw.disc.PartSize = uint32(binary.Size(part{})) //nolint:gosec
	cw.disc.PartOff = uint64(cw.written)           //nolint:gosec
	cw.disc.PartHash = sha1.Sum(parts.Bytes())     //nolint:gosec

	if err := cw.writePadded(parts.Bytes()); err != nil {
		return err
	}

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
