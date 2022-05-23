package zero

import "io"

type reader struct{}

func (reader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}

	return len(p), nil
}

// NewReader returns an io.Reader that behaves like /dev/zero in that when
// read from will always return an unlimited stream of zero bytes.
func NewReader() io.Reader {
	return new(reader)
}
