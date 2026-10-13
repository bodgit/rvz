package fst_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/bodgit/rvz/internal/fst"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type entry struct {
	dir          bool
	offset, size uint32
}

// disc returns a disc with an FST at 0x1000 holding the entries after the
// root, with offsets and sizes stored shifted right by shift.
func disc(entries []entry, shift uint) []byte {
	const fstOffset = 0x1000

	b := make([]byte, 0x2000)

	size := uint32((len(entries) + 1) * 12) //nolint:gosec // test data is small

	binary.BigEndian.PutUint32(b[0x424:], fstOffset>>shift)
	binary.BigEndian.PutUint32(b[0x428:], size>>shift)

	root := b[fstOffset:]
	root[0] = 1
	binary.BigEndian.PutUint32(root[8:], uint32(len(entries)+1)) //nolint:gosec // test data is small

	for i, e := range entries {
		x := b[fstOffset+(i+1)*12:]
		if e.dir {
			x[0] = 1
		}

		binary.BigEndian.PutUint32(x[4:], e.offset>>shift)
		binary.BigEndian.PutUint32(x[8:], e.size)
	}

	return b
}

func TestEnd(t *testing.T) {
	t.Parallel()

	entries := []entry{
		{offset: 0x10000, size: 0x1234},
		{dir: true, offset: 0, size: 5},
		{offset: 0x20000, size: 0},               // empty, ignored
		{offset: 0x30000, size: 0x8000},          // ends at 0x38000
		{offset: 0x34000, size: 0x4000},          // also ends at 0x38000, ignored
		{offset: 0x40000, size: 0x100000000 - 1}, // ends beyond 4 GiB
	}

	tables := []struct {
		name   string
		shift  uint
		offset int64
		end    int64
		ok     bool
	}{
		{"before any file", 0, 0x100, 0, false},
		{"start of file", 0, 0x10000, 0x11234, true},
		{"last byte of file", 0, 0x11233, 0x11234, true},
		{"end of file", 0, 0x11234, 0, false},
		{"empty file", 0, 0x20000, 0, false},
		{"same end", 0, 0x36000, 0x38000, true},
		{"large file", 0, 0x50000, 0x40000 + 0x100000000 - 1, true},
		{"after every file", 0, 0x200000000, 0, false},
		{"Wii offsets", 2, 0x10000, 0x11234, true},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			f, err := fst.Read(bytes.NewReader(disc(entries, table.shift)), table.shift)
			require.NoError(t, err)

			assert.Equal(t, int64(0x1000+(len(entries)+1)*12), f.TableEnd())

			end, ok := f.End(table.offset)
			assert.Equal(t, table.ok, ok)
			assert.Equal(t, table.end, end)
		})
	}
}

func TestEndNil(t *testing.T) {
	t.Parallel()

	var f *fst.Files

	_, ok := f.End(0)
	assert.False(t, ok)
}

func TestReadErrors(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name   string
		mangle func([]byte)
	}{
		{"too small", func(b []byte) { binary.BigEndian.PutUint32(b[0x428:], 4) }},
		{"too large", func(b []byte) { binary.BigEndian.PutUint32(b[0x428:], 0xffffffff) }},
		{"outside disc", func(b []byte) { binary.BigEndian.PutUint32(b[0x424:], 0x100000) }},
		{"root not a directory", func(b []byte) { b[0x1000] = 0 }},
		{"too many entries", func(b []byte) { binary.BigEndian.PutUint32(b[0x1008:], 1000) }},
		{"no entries", func(b []byte) { binary.BigEndian.PutUint32(b[0x1008:], 0) }},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			b := disc([]entry{{offset: 0x10000, size: 0x100}}, 0)
			table.mangle(b)

			_, err := fst.Read(bytes.NewReader(b), 0)
			assert.Error(t, err)
		})
	}

	_, err := fst.Read(bytes.NewReader(make([]byte, 0x100)), 0)
	assert.Error(t, err, "disc too small for the header")
}
