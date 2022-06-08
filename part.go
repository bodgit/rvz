package rvz

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec
	"errors"
	"io"
	"sync"

	"github.com/bodgit/rvz/internal/util"
	"github.com/bodgit/rvz/internal/zero"
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
)

type partReader struct {
	h0 [clusters]*bytes.Buffer
	h1 [subGroup]io.Writer
	h2 io.Writer

	cluster [clusters]*bytes.Buffer

	buf []byte
	br  *bytes.Reader

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

	for i := 0; i < clusters; i++ {
		pr.h0[i].Reset()
		pr.cluster[i].Reset()
	}

	i, j := 0, 0

	for {
		h.Reset()

		var n int64
		//nolint:nestif
		if n, err = io.CopyN(pr.cluster[i], io.TeeReader(pr.gr, h), blockSize); err != nil {
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

			if _, err = io.CopyN(pr.cluster[k], io.TeeReader(zero.NewReader(), h), blockSize); err != nil {
				return
			}

			_, _ = pr.h0[k].Write(h.Sum(nil))
		}

		_, _ = io.CopyN(pr.h0[k], zero.NewReader(), h0Padding)
	}

	buf := make([]byte, hashSize)

	// Calculate the H1 hashes
	for i := 0; i < subGroup; i++ {
		for j := 0; j < subGroup; j++ {
			h.Reset()
			_, _ = io.CopyBuffer(h, io.LimitReader(bytes.NewReader(pr.h0[i*subGroup+j].Bytes()), h0Size), buf)
			_, _ = pr.h1[i].Write(h.Sum(nil))
		}

		_, _ = io.CopyN(pr.h1[i], zero.NewReader(), h1Padding)
	}

	// Calculate the H2 hashes
	for i := 0; i < subGroup; i++ {
		h.Reset()
		_, _ = io.CopyBuffer(h,
			io.NewSectionReader(bytes.NewReader(pr.h0[i*subGroup].Bytes()), h0Size+h0Padding, h1Size),
			buf)
		_, _ = pr.h2.Write(h.Sum(nil))
	}

	_, _ = io.CopyN(pr.h2, zero.NewReader(), h2Padding)

	iv := make([]byte, aes.BlockSize) // 16 x 0x00

	var block cipher.Block

	if block, err = aes.NewCipher(pr.r.part[pr.p].Key[:]); err != nil {
		return
	}

	pr.buf = pr.buf[:(i * util.SectorSize)]

	var wg sync.WaitGroup

	for k := 0; k < i; k++ {
		wg.Add(1)

		k := k

		go func() {
			defer wg.Done()

			offset := k * util.SectorSize

			e := cipher.NewCBCEncrypter(block, iv)
			e.CryptBlocks(pr.buf[offset:], pr.h0[k].Bytes())

			e = cipher.NewCBCEncrypter(block, pr.buf[offset+ivOffset:offset+ivOffset+aes.BlockSize])
			e.CryptBlocks(pr.buf[offset+hashSize:], pr.cluster[k].Bytes())
		}()
	}

	wg.Wait()

	return nil
}

func (pr *partReader) Read(p []byte) (n int, err error) {
	if pr.br.Len() == 0 {
		if pr.lastGroup() {
			return 0, io.EOF
		}

		if err = pr.read(); err != nil {
			return
		}

		pr.br.Reset(pr.buf)
	}

	n, err = pr.br.Read(p)

	return
}

func newPartReader(r *reader, p, d int) io.Reader {
	pr := &partReader{
		p: p,
		d: d,
		g: int(r.part[p].Data[d].GroupIndex),
		r: r,
	}

	pr.buf = make([]byte, 0, util.SectorSize*clusters) // 2 MiB
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
