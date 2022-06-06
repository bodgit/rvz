package rvz

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec
	"encoding/binary"
	"errors"
	"io"

	"github.com/bodgit/plumbing"
	"github.com/bodgit/rvz/internal/packed"
	"github.com/bodgit/rvz/internal/util"
	"github.com/bodgit/rvz/internal/zero"
	"github.com/connesc/cipherio"
)

const (
	// Extension is the conventional file extension used.
	Extension = ".rvz"

	rvzMagic uint32 = 0x52565a01 // 'R', 'V', 'Z', 0x01

	compressed     uint32 = 1 << 31
	compressedMask        = compressed - 1

	gameCube = 1
	wii      = 2
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

func (d *disc) partReader(ra io.ReaderAt) io.Reader {
	return io.NewSectionReader(ra, int64(d.PartOff), int64(d.NumPart*d.PartSize))
}

func (d *disc) rawReader(ra io.ReaderAt) io.Reader {
	return io.NewSectionReader(ra, int64(d.RawDataOff), int64(d.RawDataSize))
}

func (d *disc) groupReader(ra io.ReaderAt) io.Reader {
	return io.NewSectionReader(ra, int64(d.GroupOff), int64(d.GroupSize))
}

type partData struct {
	FirstSector uint32
	NumSector   uint32
	GroupIndex  uint32
	NumGroup    uint32
}

type part struct {
	Key  [aes.BlockSize]byte
	Data [2]partData
}

type raw struct {
	RawDataOff  uint64
	RawDataSize uint64
	GroupIndex  uint32
	NumGroup    uint32
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

type except struct {
	Offset uint16
	Hash   [sha1.Size]byte
}

type reader struct {
	ra io.ReaderAt

	header header
	disc   disc
	part   []part
	raw    []raw
	group  []group

	r          io.Reader
	offset     int64
	nextOffset int64
}

func (r *reader) decompressor(reader io.Reader) (io.ReadCloser, error) {
	dcomp := decompressor(r.disc.Compression)
	if dcomp == nil {
		return nil, errors.New("rvz: unsupported algorithm")
	}

	return dcomp(r.disc.ComprData[0:r.disc.ComprDataLen], reader)
}

//nolint:cyclop,unparam
func (r *reader) groupReader(g int, offset int64, partition bool) (rc io.ReadCloser, exceptions []except, err error) {
	group := r.group[g]

	switch {
	case group.compressed():
		rc, err = r.decompressor(io.NewSectionReader(r.ra, group.offset(), group.size()))
		if err != nil {
			return nil, nil, err
		}
	case group.size() == 0:
		limit := int64(r.disc.ChunkSize)
		if partition {
			limit = limit / util.SectorSize * (util.SectorSize - hashSize)
		}

		rc = io.NopCloser(io.LimitReader(zero.NewReader(), limit))
	default:
		rc = io.NopCloser(io.NewSectionReader(r.ra, group.offset(), group.size()))
	}

	//nolint:nestif
	if partition {
		wc := new(plumbing.WriteCounter)
		tr := io.TeeReader(rc, wc)

		var numExceptions uint16
		if err = binary.Read(tr, binary.BigEndian, &numExceptions); err != nil {
			return nil, nil, err
		}

		if numExceptions > 0 {
			return nil, nil, errors.New("TODO handle exceptions")
		}

		// No compression, data starts on the next 4 byte boundary
		if !group.compressed() {
			if _, err = io.CopyN(io.Discard, rc, (group.offset()+int64(wc.Count()))%4); err != nil {
				return nil, nil, err
			}
		}
	}

	if group.PackedSize != 0 {
		rc, err = packed.NewReadCloser(rc, offset)
		if err != nil {
			return nil, nil, err
		}
	}

	return rc, nil, nil
}

type rawReader struct {
	i, g   int
	r      *reader
	gr     io.ReadCloser
	offset int64
}

func (rr *rawReader) lastGroup() bool {
	return rr.g == int(rr.r.raw[rr.i].GroupIndex+rr.r.raw[rr.i].NumGroup)
}

func (rr *rawReader) Read(p []byte) (n int, err error) {
	if rr.gr == nil {
		if rr.gr, _, err = rr.r.groupReader(rr.g, rr.offset, false); err != nil {
			return
		}
	}

	n, err = rr.gr.Read(p)
	rr.offset += int64(n)

	if err != nil {
		if !errors.Is(err, io.EOF) {
			return
		}

		if err = rr.gr.Close(); err != nil {
			return
		}

		rr.g++

		// Last group in the raw area?
		if rr.lastGroup() {
			return n, io.EOF
		}

		if rr.gr, _, err = rr.r.groupReader(rr.g, rr.offset, false); err != nil {
			return
		}
	}

	return n, nil
}

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

	blockSize = (util.SectorSize - hashSize) / blocksPerCluster

	ivOffset = 0x03d0
)

type partReader struct {
	h0 [clusters]*bytes.Buffer
	h1 [subGroup]io.Writer
	h2 io.Writer

	cluster [clusters]*bytes.Buffer

	buf *bytes.Buffer

	p, d, g int
	r       *reader
	gr      io.ReadCloser
	offset  int64
}

func (pr *partReader) lastGroup() bool {
	p := pr.r.part[pr.p].Data[pr.d]

	return pr.g == int(p.GroupIndex+p.NumGroup)
}

//nolint:cyclop,funlen,gocognit
func (pr *partReader) read() (err error) {
	if pr.gr == nil {
		if pr.gr, _, err = pr.r.groupReader(pr.g, pr.offset, true); err != nil {
			return
		}
	}

	h := sha1.New() //nolint:gosec

	i, j := 0, 0

	for {
		h.Reset()

		var n int64
		//nolint:nestif
		if n, err = io.CopyN(io.MultiWriter(pr.cluster[i], h), pr.gr, blockSize); err != nil {
			if errors.Is(err, io.EOF) && j == 0 && n == 0 {
				if err = pr.gr.Close(); err != nil {
					return
				}

				pr.g++

				if !pr.lastGroup() {
					if pr.gr, _, err = pr.r.groupReader(pr.g, pr.offset, true); err != nil {
						return
					}

					continue
				}
			} else {
				return
			}
		} else {
			pr.offset += n
			_, _ = pr.h0[i].Write(h.Sum(nil))
		}

		if pr.lastGroup() {
			if err = pr.gr.Close(); err != nil {
				return
			}

			break
		}

		j++

		if j == blocksPerCluster {
			j = 0
			_, _ = io.CopyN(pr.h0[i], zero.NewReader(), h0Padding)
			i++

			if i == clusters {
				break
			}
		}
	}

	// Zero-fill any remaining clusters, calculating the H0 hashes as we go
	for k := i; k < clusters; k++ {
		for j := 0; j < blocksPerCluster; j++ {
			h.Reset()

			if _, err = io.CopyN(io.MultiWriter(pr.cluster[k], h), zero.NewReader(), blockSize); err != nil {
				return
			}

			_, _ = pr.h0[k].Write(h.Sum(nil))
		}

		_, _ = io.CopyN(pr.h0[k], zero.NewReader(), h0Padding)
	}

	// Calculate the H1 hashes
	for i := 0; i < subGroup; i++ {
		for j := 0; j < subGroup; j++ {
			h.Reset()
			_, _ = io.Copy(h, io.LimitReader(bytes.NewReader(pr.h0[i*subGroup+j].Bytes()), h0Size))
			_, _ = pr.h1[i].Write(h.Sum(nil))
		}

		_, _ = io.CopyN(pr.h1[i], zero.NewReader(), h1Padding)
	}

	// Calculate the H2 hashes
	for i := 0; i < subGroup; i++ {
		h.Reset()
		_, _ = io.Copy(h, io.NewSectionReader(bytes.NewReader(pr.h0[i*subGroup].Bytes()), h0Size+h0Padding, h1Size))
		_, _ = pr.h2.Write(h.Sum(nil))
	}

	_, _ = io.CopyN(pr.h2, zero.NewReader(), h2Padding)

	hashIV := make([]byte, aes.BlockSize) // 16 x 0x00
	clusterIV := make([]byte, aes.BlockSize)

	var block cipher.Block

	if block, err = aes.NewCipher(pr.r.part[pr.p].Key[:]); err != nil {
		return
	}

	buf := new(bytes.Buffer)
	buf.Grow(hashSize)

	for k := 0; k < i; k++ {
		buf.Reset()

		wc := cipherio.NewBlockWriter(io.MultiWriter(pr.buf, buf), cipher.NewCBCEncrypter(block, hashIV))
		_, _ = io.Copy(wc, pr.h0[k])

		if err = wc.Close(); err != nil {
			return
		}

		copy(clusterIV, buf.Bytes()[ivOffset:])

		wc = cipherio.NewBlockWriter(pr.buf, cipher.NewCBCEncrypter(block, clusterIV))
		_, _ = io.Copy(wc, pr.cluster[k])

		if err = wc.Close(); err != nil {
			return
		}
	}

	return nil
}

func (pr *partReader) Read(p []byte) (n int, err error) {
	if pr.buf.Len() == 0 {
		if pr.lastGroup() {
			return 0, io.EOF
		}

		if err = pr.read(); err != nil {
			return
		}
	}

	n, err = pr.buf.Read(p)

	return
}

func (r *reader) partReader(p, d int) io.Reader {
	pr := &partReader{
		p:   p,
		d:   d,
		g:   int(r.part[p].Data[d].GroupIndex),
		r:   r,
		buf: new(bytes.Buffer),
	}

	pr.buf.Grow(util.SectorSize * clusters) // 2 MiB

	h1 := make([][]io.Writer, subGroup)
	for i := range h1 {
		h1[i] = make([]io.Writer, 0, subGroup)
	}

	for i := range pr.h0 {
		pr.h0[i] = new(bytes.Buffer)
		pr.h0[i].Grow(hashSize) // 0x400

		j := i / subGroup

		h1[j] = append(h1[j], pr.h0[i])
	}

	for i := range pr.cluster {
		pr.cluster[i] = new(bytes.Buffer)
		pr.cluster[i].Grow(util.SectorSize - hashSize) // 0x7c00
	}

	for i := range pr.h1 {
		pr.h1[i] = io.MultiWriter(h1[i]...)
	}

	pr.h2 = io.MultiWriter(pr.h1[:]...)

	return pr
}

func (r *reader) nextReader() (err error) {
	for i, x := range r.raw {
		if r.offset == int64(x.RawDataOff) {
			r.r, r.nextOffset = &rawReader{
				i:      i,
				g:      int(r.raw[i].GroupIndex),
				r:      r,
				offset: int64(x.RawDataOff),
			}, int64(x.RawDataOff+x.RawDataSize)

			return
		}
	}

	for i, x := range r.part {
		for j := range x.Data {
			if r.offset == int64(x.Data[j].FirstSector*util.SectorSize) && x.Data[j].NumSector > 0 {
				r.r = r.partReader(i, j)

				r.nextOffset = int64(x.Data[j].FirstSector+x.Data[j].NumSector) * util.SectorSize

				return
			}
		}
	}

	return errors.New("rvz: cannot find reader")
}

func (r *reader) Read(p []byte) (n int, err error) {
	if r.r == nil {
		if err = r.nextReader(); err != nil {
			return
		}
	}

	n, err = r.r.Read(p)
	r.offset += int64(n)

	if err != nil {
		if !errors.Is(err, io.EOF) {
			return
		}

		if r.offset != r.nextOffset {
			return n, io.ErrUnexpectedEOF
		}

		r.r, err = nil, nil

		if r.offset == int64(r.header.IsoFileSize) {
			return n, io.EOF
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

	// Make sure every area starts on a sector boundary, which is mostly
	// for the benefit of the area at the beginning of the disc
	for i := range r.raw {
		remain := r.raw[i].RawDataOff % util.SectorSize
		r.raw[i].RawDataOff -= remain
		r.raw[i].RawDataSize += remain
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
//nolint:cyclop,funlen
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

	if r.header.Magic != rvzMagic {
		return nil, errors.New("rvz: bad magic")
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

	switch r.disc.DiscType {
	case gameCube:
	case wii:
		break
	default:
		return nil, errors.New("rvz: invalid disc type")
	}

	switch r.disc.ChunkSize {
	case util.SectorSize << 0: //  32 KiB
	case util.SectorSize << 1: //  64 KiB
	case util.SectorSize << 2: // 128 KiB
	case util.SectorSize << 3: // 256 KiB
	case util.SectorSize << 4: // 512 KiB
	case util.SectorSize << 5: //   1 MiB
		break
	default:
		// Multiple of 2 MiB
		if r.disc.ChunkSize%(util.SectorSize<<6) != 0 {
			return nil, errors.New("rvz: bad chunk size")
		}
	}

	h.Reset()

	if r.disc.NumPart > 0 {
		r.part = make([]part, r.disc.NumPart)
		if int(r.disc.PartSize) != binary.Size(r.part[0]) {
			return nil, errors.New("rvz: part struct has wrong size")
		}

		if err := binary.Read(io.TeeReader(r.disc.partReader(ra), h), binary.BigEndian, &r.part); err != nil {
			return nil, err
		}
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

	return r, nil
}
