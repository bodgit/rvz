package packed

import (
	"encoding/binary"
	"sort"

	"github.com/bodgit/rvz/internal/padding"
	"github.com/bodgit/rvz/internal/util"
)

// Files finds where the file containing a disc offset ends.
type Files interface {
	End(offset int64) (int64, bool)
}

// junk is a run of padding in the data being packed.
type junk struct {
	start, end int
	seed       [padding.SeedSize]byte
}

// findJunk finds the runs of padding in b, which starts offset bytes into
// the disc. As with Dolphin, padding is looked for after skipping any zeroes
// at the start of each sector and, if files is given, after each file that
// ends part way through a sector.
func findJunk(b []byte, offset int64, zeroes bool, files Files) []junk {
	var found []junk

	for pos := 0; pos < len(b); {
		// Skip the zeroes that typically follow a file
		n := 0
		for pos+n < len(b) && b[pos+n] == 0 {
			n++
		}

		// Without compression, a long run of zeroes is better stored as
		// padding from a seed of zeroes
		if zeroes && n > padding.SeedSize {
			found = append(found, junk{start: pos, end: pos + n})
		}

		pos += n
		offset += int64(n)

		// The padding is seeded again at the start of each sector
		inSector := int(offset % util.SectorSize)
		size := min(util.SectorSize-inSector, len(b)-pos)

		seed, n := padding.Seed(b[pos:pos+size], inSector)
		if n > 0 {
			found = append(found, junk{start: pos, end: pos + n, seed: seed})
		}

		// If a file ends before the sector does, look again after it
		if files != nil {
			if end, ok := files.End(offset + int64(n)); ok && end < offset+int64(size) {
				pos += int(end - offset)
				offset = end

				continue
			}
		}

		pos += size
		offset += int64(size)
	}

	return found
}

// Pack appends src packed to dst, where src starts offset bytes into the
// disc. If compression won't be used, long runs of zeroes are also stored
// as padding. If files is given, it is used to find padding that follows a
// file. It returns false if src has no padding worth storing as a seed, in
// which case src should be stored as is.
func Pack(dst, src []byte, offset int64, compression bool, files Files) ([]byte, bool) {
	found := findJunk(src, offset, !compression, files)

	for cur, first := 0, true; cur < len(src); first = false {
		junkStart, junkEnd := len(src), len(src)

		var seed *[padding.SeedSize]byte

		// Find the next run of padding that is worth storing as a seed
		if len(src)-cur > padding.SeedSize {
			i := sort.Search(len(found), func(i int) bool {
				return found[i].end > cur+padding.SeedSize
			})

			if i < len(found) && found[i].start+padding.SeedSize < len(src) {
				junkStart = max(cur, found[i].start)
				junkEnd = min(len(src), found[i].end)
				seed = &found[i].seed
			}
		}

		if first && junkStart == len(src) {
			return dst, false
		}

		if n := junkStart - cur; n > 0 {
			dst = binary.BigEndian.AppendUint32(dst, uint32(n)) //nolint:gosec // at most a chunk
			dst = append(dst, src[cur:junkStart]...)
			cur = junkStart
		}

		if n := junkEnd - cur; n > 0 {
			dst = binary.BigEndian.AppendUint32(dst, uint32(n)|padded) //nolint:gosec // at most a chunk
			dst = append(dst, seed[:]...)
			cur = junkEnd
		}
	}

	return dst, true
}
