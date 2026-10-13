package padding

import (
	"bytes"
	"encoding/binary"

	"github.com/bodgit/rvz/internal/util"
)

// SeedSize is the size of a seed in bytes.
const SeedSize = initialSize * 4

// A state is the generator state in its output form, where each word holds
// the next four bytes of output as a big-endian value.
type state [maximumSize]uint32

func (s *state) forward() {
	for i := range lag {
		s[i] ^= s[i+maximumSize-lag]
	}

	for i := lag; i < maximumSize; i++ {
		s[i] ^= s[i-lag]
	}
}

// backward undoes forward for the words from start up to end.
func (s *state) backward(start, end int) {
	for i := min(end, maximumSize); i > max(lag, start); i-- {
		s[i-1] ^= s[i-1-lag]
	}

	for i := min(end, lag); i > start; i-- {
		s[i-1] ^= s[i-1+maximumSize-lag]
	}
}

// reinitialize rewinds the state to the one created from the seed, which is
// returned, and checks the seed would create it.
func (s *state) reinitialize() ([initialSize]uint32, bool) {
	for range 4 {
		s.backward(0, maximumSize)
	}

	// Reconstruct the bits lost by the output shifting by 18 instead of
	// 16. Bits 16 and 17 of the first word can't be recovered but don't
	// affect the output
	for i := range initialSize {
		s[i] = s[i]&0xff00ffff | s[i]<<2&0x00fc0000 | (s[i+16]^s[i+15])<<9&0x00030000
	}

	var seed [initialSize]uint32

	copy(seed[:], s[:initialSize])

	for i := initialSize; i < maximumSize; i++ {
		calculated := s[i-17]<<23 ^ s[i-16]>>9 ^ s[i-1]
		actual := s[i]&0xff00ffff | s[i]<<2&0x00fc0000

		if calculated&0xfffcffff != actual {
			return seed, false
		}

		s[i] = calculated
	}

	// Convert back to the output form
	for i, x := range s {
		s[i] = x&0xff00ffff | x>>2&0x00ff0000
	}

	for range 4 {
		s.forward()
	}

	return seed, true
}

// recoverSeed finds the seed from at least one block of words of padding
// that start at the given word offset into a sector. It also returns the
// state at the start of the sector.
func recoverSeed(words []uint32, offset int) ([initialSize]uint32, *state, bool) {
	var seed [initialSize]uint32

	if len(words) < maximumSize {
		return seed, nil, false
	}

	// Bail out early on anything that can't be padding
	for _, w := range words[:maximumSize] {
		if w&0x00c00000 != w>>2&0x00c00000 {
			return seed, nil, false
		}
	}

	mod, div := offset%maximumSize, offset/maximumSize

	s := new(state)
	copy(s[mod:], words[:maximumSize-mod])
	copy(s[:mod], words[maximumSize-mod:maximumSize])

	s.backward(0, mod)

	for range div {
		s.backward(0, maximumSize)
	}

	seed, ok := s.reinitialize()

	return seed, s, ok
}

// Seed finds the seed that generates the padding at the start of b, which
// starts offset bytes into a sector. It returns the seed and how many bytes
// of b it generates, which is 0 if b doesn't start with padding. At least
// one block of 2084 bytes of padding is needed to find a seed.
func Seed(b []byte, offset int) ([SeedSize]byte, int) {
	var out [SeedSize]byte

	offset %= util.SectorSize

	// Only whole words are used to find the seed, and only one block of
	// them is needed
	skip := (4 - offset%4) % 4
	if len(b)-skip < blockSize {
		return out, 0
	}

	words := make([]uint32, maximumSize)
	for i := range words {
		words[i] = binary.BigEndian.Uint32(b[skip+i*4:])
	}

	seed, s, ok := recoverSeed(words, (offset+skip)/4)
	if !ok {
		return out, 0
	}

	for i, x := range seed {
		binary.BigEndian.PutUint32(out[i*4:], x)
	}

	// Count how many bytes the seed generates from the start of b. Unlike
	// Dolphin, this uses the block holding the first byte of b rather than
	// the first whole word, which can be in the next block
	for range offset / blockSize {
		s.forward()
	}

	return out, s.matches(b, offset%blockSize)
}

// matches returns how many bytes at the start of b are generated from the
// state, starting pos bytes into its current block. Each block is generated
// and compared as a whole.
func (s *state) matches(b []byte, pos int) int {
	var block [blockSize]byte

	n := 0

	for n < len(b) {
		for i, w := range s {
			binary.BigEndian.PutUint32(block[i*4:], w)
		}

		want := block[pos:min(blockSize, pos+len(b)-n)]
		got := b[n : n+len(want)]

		if !bytes.Equal(want, got) {
			for i := range want {
				if want[i] != got[i] {
					return n + i
				}
			}
		}

		n += len(want)
		pos = 0

		s.forward()
	}

	return n
}
