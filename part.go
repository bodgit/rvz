package rvz

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec
	"io"
	"runtime"

	"github.com/bodgit/plumbing"
	"github.com/bodgit/rvz/internal/util"
	"golang.org/x/sync/errgroup"
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

	blockSize = (util.SectorSize - hashSize) / blocksPerCluster

	ivOffset = 0x03d0

	groupSize = util.SectorSize * clusters // 2 MiB
)

func min(x, y int) int {
	if x < y {
		return x
	}

	return y
}

type partReader struct {
	h0 [clusters]*bytes.Buffer
	h1 [subGroup]io.Writer
	h2 io.Writer

	cluster [clusters]*bytes.Buffer

	buf []byte
	br  *bytes.Reader

	p, d   int
	r      *reader
	sector int
}

func (pr *partReader) groupOffset(g int) int64 {
	return (int64(g) - int64(pr.r.part[pr.p].Data[pr.d].GroupIndex)) * pr.r.disc.chunkSize(true)
}

func (pr *partReader) reset() {
	for i := 0; i < clusters; i++ {
		pr.h0[i].Reset()
		pr.cluster[i].Reset()
	}
}

func (pr *partReader) readGroup(i int) error {
	ss := i * pr.r.disc.sectorsPerChunk()
	g := pr.sectorToGroup(pr.sector + ss)

	h := sha1.New() //nolint:gosec

	split := min(ss+pr.r.disc.sectorsPerChunk(), int(pr.r.part[pr.p].Data[pr.d].NumSector)-pr.sector)
	if split < ss {
		split = ss
	}

	var (
		rc  io.ReadCloser
		err error
		zr  = plumbing.DevZero()
		r   io.Reader
	)

	if split > ss {
		rc, _, err = pr.r.groupReader(g, pr.groupOffset(g), true)
		if err != nil {
			return err
		}
		defer rc.Close()
	}

	for j := ss; j < ss+pr.r.disc.sectorsPerChunk(); j++ {
		if j < split {
			r = rc
		} else {
			r = zr
		}

		for k := 0; k < blocksPerCluster; k++ {
			h.Reset()

			if _, err := io.CopyN(pr.cluster[j], io.TeeReader(r, h), blockSize); err != nil {
				return err
			}

			_, _ = pr.h0[j].Write(h.Sum(nil))
		}

		_, _ = io.CopyN(pr.h0[j], plumbing.DevZero(), h0Padding)
	}

	return nil
}

func (pr *partReader) writeHashes() {
	h := sha1.New() //nolint:gosec

	buf := make([]byte, hashSize)

	// Calculate the H1 hashes
	for i := 0; i < subGroup; i++ {
		for j := 0; j < subGroup; j++ {
			h.Reset()
			_, _ = io.CopyBuffer(h, io.LimitReader(bytes.NewReader(pr.h0[i*subGroup+j].Bytes()), h0Size), buf)
			_, _ = pr.h1[i].Write(h.Sum(nil))
		}

		_, _ = io.CopyN(pr.h1[i], plumbing.DevZero(), h1Padding)
	}

	// Calculate the H2 hashes
	for i := 0; i < subGroup; i++ {
		h.Reset()
		_, _ = io.CopyBuffer(h,
			io.NewSectionReader(bytes.NewReader(pr.h0[i*subGroup].Bytes()), h0Size+h0Padding, h1Size),
			buf)
		_, _ = pr.h2.Write(h.Sum(nil))
	}

	_, _ = io.CopyN(pr.h2, plumbing.DevZero(), h2Padding)
}

//nolint:gochecknoglobals
var iv = make([]byte, aes.BlockSize) // 16 x 0x00

func (pr *partReader) encryptSector(sector int) error {
	block, err := aes.NewCipher(pr.r.part[pr.p].Key[:])
	if err != nil {
		return err
	}

	offset := sector * util.SectorSize

	e := cipher.NewCBCEncrypter(block, iv)
	e.CryptBlocks(pr.buf[offset:], pr.h0[sector].Bytes())

	e = cipher.NewCBCEncrypter(block, pr.buf[offset+ivOffset:offset+ivOffset+aes.BlockSize])
	e.CryptBlocks(pr.buf[offset+hashSize:], pr.cluster[sector].Bytes())

	return nil
}

func (pr *partReader) sectorToGroup(sector int) int {
	return int(pr.r.part[pr.p].Data[pr.d].GroupIndex) + sector/(int(pr.r.disc.ChunkSize)/util.SectorSize)
}

func (pr *partReader) read() (err error) {
	eg := new(errgroup.Group)
	eg.SetLimit(runtime.NumCPU())

	pr.reset()

	for i := 0; i < groupSize/int(pr.r.disc.ChunkSize); i++ {
		i := i

		eg.Go(func() error {
			return pr.readGroup(i)
		})
	}

	if err = eg.Wait(); err != nil {
		return
	}

	pr.writeHashes()

	sectors := min(clusters, int(pr.r.part[pr.p].Data[pr.d].NumSector)-pr.sector)

	pr.buf = pr.buf[:(sectors * util.SectorSize)]

	for i := 0; i < sectors; i++ {
		i := i

		eg.Go(func() error {
			return pr.encryptSector(i)
		})
	}

	if err = eg.Wait(); err != nil {
		return
	}

	return nil
}

func (pr *partReader) Read(p []byte) (n int, err error) {
	if pr.br.Len() == 0 {
		if pr.sector == int(pr.r.part[pr.p].Data[pr.d].NumSector) {
			return 0, io.EOF
		}

		if err = pr.read(); err != nil {
			return
		}

		pr.br.Reset(pr.buf)

		pr.sector += pr.br.Len() / util.SectorSize
	}

	n, err = pr.br.Read(p)

	return
}

func newPartReader(r *reader, p, d int) io.Reader {
	pr := &partReader{
		p: p,
		d: d,
		r: r,
	}

	pr.buf = make([]byte, 0, groupSize) // 2 MiB
	pr.br = bytes.NewReader(pr.buf)

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
