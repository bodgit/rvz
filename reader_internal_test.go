package rvz

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroupOffset(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name   string
		offset uint32
		want   int64
	}{
		{"zero", 0, 0},
		{"below 4 GiB", 1<<30 - 1, 1<<32 - 4},
		{"4 GiB", 1 << 30, 1 << 32},
		{"maximum", 1<<32 - 1, 1<<34 - 4},
	}

	for _, table := range tables {
		table := table

		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			g := group{Offset: table.offset}
			assert.Equal(t, table.want, g.offset())
		})
	}
}
