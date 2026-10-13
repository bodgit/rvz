// Package fst reads the file system table of a GameCube or Wii disc, which
// is used to find where each file ends.
package fst

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
)

const (
	headerOffset = 0x424
	entrySize    = 12

	// The same limit as Dolphin, which is more than the RAM of a Wii.
	maxSize = 128 << 20
)

var (
	errBadSize      = errors.New("fst: bad size")
	errNotDirectory = errors.New("fst: root is not a directory")
	errBadCount     = errors.New("fst: bad number of entries")
)

// Files holds where each file on the disc is.
type Files struct {
	start, end []int64 // sorted by end
	tableEnd   int64
}

// Read reads the file system table from ra, which is either a GameCube disc
// or the decrypted data of a Wii partition. File offsets are shifted left
// by shift, which is 0 for GameCube and 2 for Wii.
func Read(ra io.ReaderAt, shift uint) (*Files, error) {
	b, tableEnd, err := readTable(ra, shift)
	if err != nil {
		return nil, err
	}

	// The root directory holds the number of entries
	if b[0]&1 == 0 {
		return nil, errNotDirectory
	}

	// The count includes the root itself
	n := int64(binary.BigEndian.Uint32(b[8:]))
	if n < 1 || n*entrySize > int64(len(b)) {
		return nil, errBadCount
	}

	f := index(b[:n*entrySize], shift)
	f.tableEnd = tableEnd

	return f, nil
}

// readTable returns the file system table and where it ends.
func readTable(ra io.ReaderAt, shift uint) ([]byte, int64, error) {
	var header [8]byte
	if _, err := ra.ReadAt(header[:], headerOffset); err != nil {
		return nil, 0, fmt.Errorf("fst: reading header: %w", err)
	}

	offset := int64(binary.BigEndian.Uint32(header[0:])) << shift
	size := int64(binary.BigEndian.Uint32(header[4:])) << shift

	if size < entrySize || size > maxSize {
		return nil, 0, errBadSize
	}

	b := make([]byte, size)
	if _, err := ra.ReadAt(b, offset); err != nil {
		return nil, 0, fmt.Errorf("fst: reading table: %w", err)
	}

	return b, offset + size, nil
}

// index builds the sorted list of where each file starts and ends from the
// entries in b.
func index(b []byte, shift uint) *Files {
	ends := make(map[int64]int64)

	for e := range slices.Chunk(b[entrySize:], entrySize) {
		// Skip directories and empty files
		size := int64(binary.BigEndian.Uint32(e[8:]))
		if e[0]&1 != 0 || size == 0 {
			continue
		}

		start := int64(binary.BigEndian.Uint32(e[4:])) << shift

		// As with Dolphin, the first file to end at an offset wins
		if _, ok := ends[start+size]; !ok {
			ends[start+size] = start
		}
	}

	f := &Files{
		start: make([]int64, 0, len(ends)),
		end:   make([]int64, 0, len(ends)),
	}

	for end := range ends {
		f.end = append(f.end, end)
	}

	slices.Sort(f.end)

	for _, end := range f.end {
		f.start = append(f.start, ends[end])
	}

	return f
}

// TableEnd returns where the file system table itself ends.
func (f *Files) TableEnd() int64 {
	return f.tableEnd
}

// End returns where the file containing offset ends, if there is one.
func (f *Files) End(offset int64) (int64, bool) {
	if f == nil {
		return 0, false
	}

	// The first file that ends after offset must also start at or before
	// it to contain it
	i := sort.Search(len(f.end), func(i int) bool { return f.end[i] > offset })
	if i == len(f.end) || f.start[i] > offset {
		return 0, false
	}

	return f.end[i], true
}
