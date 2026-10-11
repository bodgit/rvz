package packed_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"testing/iotest"

	"github.com/bodgit/rvz/internal/packed"
	"github.com/bodgit/rvz/internal/padding"
	"github.com/stretchr/testify/assert"
)

const (
	padded   = 1 << 31
	seedSize = 17 * 4
)

func seed() []byte {
	b := make([]byte, seedSize)
	for i := range b {
		b[i] = byte(i * 7)
	}

	return b
}

// stream returns a packed stream of a plain entry, an empty entry and a
// padded entry along with the data it should unpack to, which starts at
// offset.
func stream(t *testing.T, offset int64) ([]byte, []byte) {
	t.Helper()

	plain := bytes.Repeat([]byte{0xaa}, 1000)
	paddedSize := int64(5000)

	pr, err := padding.NewReadCloser(bytes.NewReader(seed()), offset+int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()

	pad := make([]byte, paddedSize)
	if _, err := io.ReadFull(pr, pad); err != nil {
		t.Fatal(err)
	}

	b := new(bytes.Buffer)
	_ = binary.Write(b, binary.BigEndian, uint32(len(plain)))
	b.Write(plain)
	_ = binary.Write(b, binary.BigEndian, uint32(0))
	_ = binary.Write(b, binary.BigEndian, uint32(padded|paddedSize))
	b.Write(seed())

	return b.Bytes(), append(plain, pad...)
}

func TestReadCloser(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name string
		wrap func(io.Reader) io.Reader
	}{
		{
			name: "whole",
			wrap: func(r io.Reader) io.Reader { return r },
		},
		{
			name: "one byte at a time",
			wrap: iotest.OneByteReader,
		},
	}

	for _, table := range tables {
		table := table

		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			offset := int64(0x12345)
			in, want := stream(t, offset)

			rc, err := packed.NewReadCloser(io.NopCloser(bytes.NewReader(in)), offset)
			if err != nil {
				t.Fatal(err)
			}

			got, err := io.ReadAll(table.wrap(rc))
			if err != nil {
				t.Fatal(err)
			}

			assert.True(t, bytes.Equal(want, got), "unpacked data doesn't match")
			assert.NoError(t, rc.Close())
		})
	}
}

func TestReadCloserTruncated(t *testing.T) {
	t.Parallel()

	in, _ := stream(t, 0)

	// Cut the stream part way through the plain entry
	rc, err := packed.NewReadCloser(io.NopCloser(bytes.NewReader(in[:500])), 0)
	if err != nil {
		t.Fatal(err)
	}

	_, err = io.ReadAll(rc)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}
