package rvz

import (
	"bytes"
	"io"
	"testing"

	"github.com/bodgit/rvz/internal/util"
	"github.com/stretchr/testify/assert"
)

func TestEmptyPartitionGroup(t *testing.T) {
	t.Parallel()

	r := &reader{
		disc: disc{
			ChunkSize: util.SectorSize,
		},
		group: []group{
			{},
		},
	}

	rc, _, err := r.groupReader(0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}

	assert.Len(t, b, int(r.disc.chunkSize(true)))
	assert.Equal(t, len(b), bytes.Count(b, []byte{0}))
}

func TestEmptyRawGroupAtEnd(t *testing.T) {
	t.Parallel()

	// One full chunk of data followed by half a chunk of zeroes
	data := bytes.Repeat([]byte{0xaa}, util.SectorSize)
	size := util.SectorSize + util.SectorSize/2

	r := &reader{
		ra: bytes.NewReader(data),
		header: header{
			IsoFileSize: uint64(size),
		},
		disc: disc{
			ChunkSize: util.SectorSize,
		},
		raw: []raw{
			{
				RawDataSize: uint64(size),
				NumGroup:    2,
			},
		},
		group: []group{
			{
				Size: util.SectorSize,
			},
			{},
		},
	}

	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, append(data, make([]byte, util.SectorSize/2)...), b)
}
