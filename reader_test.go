package rvz_test

import (
	"crypto/sha1" //nolint:gosec
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bodgit/rom/dat"
	"github.com/bodgit/rvz"
	"github.com/stretchr/testify/assert"
)

const (
	gamecube = "Nintendo - GameCube - Datfile (1942) (2022-05-22 04-27-22).dat"
	wii      = "Nintendo - Wii - Datfile (3647) (2022-01-07 22-05-54).dat"
)

//nolint:gochecknoglobals
var discs = []struct {
	name, dat, file string
}{
	{
		name: "GameCube",
		dat:  gamecube,
		file: "Gekkan Nintendo Tentou Demo 2003.9.1 (Japan)",
	},
	{
		name: "Wii",
		dat:  wii,
		file: "Metal Slug Anthology (USA)",
	},
	{
		name: "Issue #121",
		dat:  wii,
		file: "Mario Kart Wii (USA) (En,Fr,Es)",
	},
}

// redumpSHA1 returns the SHA-1 of the disc image in the datfile.
func redumpSHA1(t *testing.T, datfile, file string) string {
	t.Helper()

	b, err := os.ReadFile(filepath.Join("testdata", datfile)) //nolint:gosec // only test data is read
	if err != nil {
		t.Fatal(err)
	}

	d := new(dat.File)
	if err := xml.Unmarshal(b, d); err != nil {
		t.Fatal(err)
	}

	for i := range d.Game {
		if g := &d.Game[i]; g.Name == file && g.ROM[0].Name == file+".iso" {
			return strings.ToLower(g.ROM[0].SHA1)
		}
	}

	t.Fatal("no such disc")

	return ""
}

// readSHA1 returns the SHA-1 of the disc image in the RVZ image at path.
func readSHA1(t *testing.T, path string) string {
	t.Helper()

	f, err := os.Open(path) //nolint:gosec // only test data is read
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		_ = f.Close()
	}()

	r, err := rvz.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}

	h := sha1.New() //nolint:gosec

	if _, err := io.Copy(h, r); err != nil {
		t.Fatal(err)
	}

	return fmt.Sprintf("%02x", h.Sum(nil))
}

func TestReader(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip()
	}

	for _, disc := range discs {
		t.Run(disc.name, func(t *testing.T) {
			t.Parallel()

			got := readSHA1(t, filepath.Join("testdata", disc.file+rvz.Extension))
			assert.Equal(t, redumpSHA1(t, disc.dat, disc.file), got)
		})
	}
}

func benchmarkReader(file string) error {
	f, err := os.Open(filepath.Join("testdata", file)) //nolint:gosec // only test data is read
	if err != nil {
		return fmt.Errorf("opening %s: %w", file, err)
	}
	defer func() {
		_ = f.Close()
	}()

	r, err := rvz.NewReader(f)
	if err != nil {
		return fmt.Errorf("reading %s: %w", file, err)
	}

	if _, err := io.Copy(io.Discard, r); err != nil {
		return fmt.Errorf("decompressing %s: %w", file, err)
	}

	return nil
}

func BenchmarkReader(b *testing.B) {
	for b.Loop() {
		if err := benchmarkReader("Metal Slug Anthology (USA).rvz"); err != nil {
			b.Fatal(err)
		}
	}
}
