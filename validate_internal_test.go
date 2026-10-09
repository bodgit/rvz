package rvz

import (
	"testing"

	"github.com/bodgit/rvz/internal/util"
	"github.com/stretchr/testify/assert"
)

const testChunkSize = util.SectorSize << 2 // 128 KiB

func testHeader() header {
	return header{
		Version:           rvzVersion,
		VersionCompatible: rvzVersionReadCompatible,
		IsoFileSize:       testChunkSize * 10,
	}
}

//nolint:funlen
func TestHeaderValidate(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name   string
		modify func(*header)
		err    bool
	}{
		{
			name:   "valid header",
			modify: func(_ *header) {},
		},
		{
			name: "maximum disc size",
			modify: func(h *header) {
				h.IsoFileSize = maxIsoFileSize
			},
		},
		{
			name: "version too old",
			modify: func(h *header) {
				h.Version = rvzVersionReadCompatible - 1
			},
			err: true,
		},
		{
			name: "requires newer reader",
			modify: func(h *header) {
				h.VersionCompatible = rvzVersion + 1
			},
			err: true,
		},
		{
			name: "zero disc size",
			modify: func(h *header) {
				h.IsoFileSize = 0
			},
			err: true,
		},
		{
			name: "disc too large",
			modify: func(h *header) {
				h.IsoFileSize = maxIsoFileSize + 1
			},
			err: true,
		},
	}

	for _, table := range tables {
		table := table

		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			h := testHeader()
			table.modify(&h)

			if table.err {
				assert.Error(t, h.validate())
			} else {
				assert.NoError(t, h.validate())
			}
		})
	}
}

//nolint:funlen
func TestDiscValidate(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name   string
		modify func(*disc)
		err    bool
	}{
		{
			name:   "valid disc",
			modify: func(_ *disc) {},
		},
		{
			name: "maximum compressor data length",
			modify: func(d *disc) {
				d.ComprDataLen = byte(len(d.ComprData))
			},
		},
		{
			name: "compressor data length too long",
			modify: func(d *disc) {
				d.ComprDataLen = byte(len(d.ComprData)) + 1
			},
			err: true,
		},
		{
			name: "unsupported compression",
			modify: func(d *disc) {
				d.Compression = 0xffffffff
			},
			err: true,
		},
		{
			name: "too many partitions",
			modify: func(d *disc) {
				d.NumPart = 0xffffffff
			},
			err: true,
		},
		{
			name: "too many raw data entries",
			modify: func(d *disc) {
				d.NumRawData = 0xffffffff
			},
			err: true,
		},
		{
			name: "maximum groups",
			modify: func(d *disc) {
				d.NumGroup = 10 + 1 + 2*1
			},
		},
		{
			name: "too many groups",
			modify: func(d *disc) {
				d.NumGroup = 10 + 1 + 2*1 + 1
			},
			err: true,
		},
	}

	for _, table := range tables {
		table := table

		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			h := testHeader()
			d := disc{
				Compression: 5,
				ChunkSize:   testChunkSize,
				NumPart:     1,
				NumRawData:  1,
				NumGroup:    10,
			}
			table.modify(&d)

			if table.err {
				assert.Error(t, d.validate(&h))
			} else {
				assert.NoError(t, d.validate(&h))
			}
		})
	}
}

//nolint:funlen
func TestValidateEntries(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name   string
		modify func(*reader)
		err    bool
	}{
		{
			name:   "valid entries",
			modify: func(_ *reader) {},
		},
		{
			name: "partition data outside disc",
			modify: func(r *reader) {
				r.part[0].Data[1].NumSector++
			},
			err: true,
		},
		{
			name: "partition data group index out of range",
			modify: func(r *reader) {
				r.part[0].Data[1].GroupIndex++
			},
			err: true,
		},
		{
			name: "partition data too few groups",
			modify: func(r *reader) {
				r.part[0].Data[1].NumGroup--
			},
			err: true,
		},
		{
			name: "raw data outside disc",
			modify: func(r *reader) {
				r.raw[0].RawDataSize = r.header.IsoFileSize + 1
			},
			err: true,
		},
		{
			name: "raw data offset overflow",
			modify: func(r *reader) {
				r.raw[0].RawDataOff = 1<<64 - 1
			},
			err: true,
		},
		{
			name: "raw data group index out of range",
			modify: func(r *reader) {
				r.raw[0].GroupIndex = r.disc.NumGroup
			},
			err: true,
		},
		{
			name: "raw data too few groups",
			modify: func(r *reader) {
				r.raw[0].NumGroup--
			},
			err: true,
		},
	}

	for _, table := range tables {
		table := table

		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			// A 128 KiB raw area, followed by a partition with one
			// group for its first area and eight for the remainder,
			// filling the 10 chunk disc
			r := &reader{
				header: testHeader(),
				disc: disc{
					ChunkSize: testChunkSize,
					NumGroup:  10,
				},
				part: []part{
					{
						Data: [2]partData{
							{
								FirstSector: 4,
								NumSector:   4,
								GroupIndex:  1,
								NumGroup:    1,
							},
							{
								FirstSector: 8,
								NumSector:   32,
								GroupIndex:  2,
								NumGroup:    8,
							},
						},
					},
				},
				raw: []raw{
					{
						RawDataSize: testChunkSize,
						NumGroup:    1,
					},
				},
			}
			table.modify(r)

			if table.err {
				assert.Error(t, r.validateEntries())
			} else {
				assert.NoError(t, r.validateEntries())
			}
		})
	}
}
