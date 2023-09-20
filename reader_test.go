package rvz_test

import (
	"crypto/sha1" //nolint:gosec
	"encoding/xml"
	"errors"
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

//nolint:cyclop,funlen
func TestReader(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip()
	}

	tables := []struct {
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
	}

	for _, table := range tables {
		table := table

		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			b, err := os.ReadFile(filepath.Join("testdata", table.dat))
			if err != nil {
				t.Fatal(err)
			}

			d := new(dat.File)
			if err := xml.Unmarshal(b, d); err != nil {
				t.Fatal(err)
			}

			f, err := os.Open(filepath.Join("testdata", table.file+rvz.Extension))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			r, err := rvz.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}

			h := sha1.New() //nolint:gosec

			if _, err := io.Copy(h, r); err != nil {
				t.Fatal(err)
			}

			var g *dat.Game

			for i := range d.Game {
				if d.Game[i].Name == table.file {
					g = &d.Game[i]

					break
				}
			}

			if g == nil || g.ROM[0].Name != table.file+".iso" {
				t.Fatal(errors.New("no such disc"))
			}

			assert.Equal(t, fmt.Sprintf("%02x", h.Sum(nil)), strings.ToLower(g.ROM[0].SHA1))
		})
	}
}

func benchmarkReader(file string) error {
	f, err := os.Open(filepath.Join("testdata", file))
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := rvz.NewReader(f)
	if err != nil {
		return err
	}

	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}

	return nil
}

func BenchmarkReader(b *testing.B) {
	for n := 0; n < b.N; n++ {
		if err := benchmarkReader("Metal Slug Anthology (USA).rvz"); err != nil {
			b.Fatal(err)
		}
	}
}
