package rvz

import (
	"errors"

	"github.com/bodgit/rvz/internal/util"
)

const (
	rvzVersion               uint32 = 0x01000000
	rvzVersionReadCompatible uint32 = 0x00030000

	// The size of a dual-layer Wii disc, which is the largest possible.
	maxIsoFileSize = 8511160320
)

func ceilDiv(x, y uint64) uint64 {
	return (x + y - 1) / y
}

func (h *header) validate() error {
	if h.Version < rvzVersionReadCompatible || h.VersionCompatible > rvzVersion {
		return errors.New("rvz: unsupported version")
	}

	if h.IsoFileSize == 0 || h.IsoFileSize > maxIsoFileSize {
		return errors.New("rvz: bad disc size")
	}

	return nil
}

// validate checks the fields that determine how much is allocated for the
// partition, raw data and group tables before any of them are read.
func (d *disc) validate(h *header) error {
	if int(d.ComprDataLen) > len(d.ComprData) {
		return errors.New("rvz: bad compressor data length")
	}

	if decompressor(d.Compression) == nil {
		return errors.New("rvz: unsupported algorithm")
	}

	sectors := ceilDiv(h.IsoFileSize, util.SectorSize)

	if uint64(d.NumPart) > sectors {
		return errors.New("rvz: too many partitions")
	}

	if uint64(d.NumRawData) > sectors {
		return errors.New("rvz: too many raw data entries")
	}

	// Each raw data region and both data areas of each partition can
	// end with a partial group
	maxGroups := ceilDiv(h.IsoFileSize, uint64(d.ChunkSize)) + uint64(d.NumRawData) + 2*uint64(d.NumPart)
	if uint64(d.NumGroup) > maxGroups {
		return errors.New("rvz: too many groups")
	}

	return nil
}

func (pd *partData) validate(h *header, d *disc) error {
	if (uint64(pd.FirstSector)+uint64(pd.NumSector))*util.SectorSize > h.IsoFileSize {
		return errors.New("rvz: partition data outside disc")
	}

	if uint64(pd.GroupIndex)+uint64(pd.NumGroup) > uint64(d.NumGroup) ||
		ceilDiv(uint64(pd.NumSector), uint64(d.sectorsPerChunk())) > uint64(pd.NumGroup) {
		return errors.New("rvz: bad partition data groups")
	}

	return nil
}

func (x *raw) validate(h *header, d *disc) error {
	if x.RawDataSize > h.IsoFileSize || x.RawDataOff > h.IsoFileSize-x.RawDataSize {
		return errors.New("rvz: raw data outside disc")
	}

	if uint64(x.GroupIndex)+uint64(x.NumGroup) > uint64(d.NumGroup) ||
		ceilDiv(x.RawDataSize, uint64(d.ChunkSize)) > uint64(x.NumGroup) {
		return errors.New("rvz: bad raw data groups")
	}

	return nil
}

// validateEntries checks that every partition and raw data entry lies within
// the disc and refers to enough groups to cover it, all of which exist.
func (r *reader) validateEntries() error {
	for i := range r.part {
		for j := range r.part[i].Data {
			if err := r.part[i].Data[j].validate(&r.header, &r.disc); err != nil {
				return err
			}
		}
	}

	for i := range r.raw {
		if err := r.raw[i].validate(&r.header, &r.disc); err != nil {
			return err
		}
	}

	return nil
}
