package zero_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/bodgit/rvz/internal/zero"
	"github.com/stretchr/testify/assert"
)

const limit = 10

func TestReader(t *testing.T) {
	t.Parallel()

	r := zero.NewReader()
	b := new(bytes.Buffer)

	n, err := io.Copy(b, io.LimitReader(r, limit))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, limit, int(n))
	assert.Equal(t, limit, b.Len())
	assert.Equal(t, bytes.Repeat([]byte{0x00}, limit), b.Bytes())
}
