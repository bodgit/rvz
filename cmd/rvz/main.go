// Command rvz decompresses RVZ disc images to ISO images.
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/bodgit/plumbing"
	"github.com/bodgit/rvz"
	"github.com/schollz/progressbar/v3"
	"github.com/urfave/cli/v2"
)

const isoExtension = ".iso"

var errISOExtension = errors.New("source file already has " + isoExtension + " extension")

var (
	version = "dev"
	commit  = "none"    //nolint:gochecknoglobals
	date    = "unknown" //nolint:gochecknoglobals
)

//nolint:gochecknoinits
func init() {
	cli.VersionFlag = &cli.BoolFlag{
		Name:    "version",
		Aliases: []string{"V"},
		Usage:   "print the version",
	}
}

func decompress(c *cli.Context) error {
	if c.NArg() < 1 {
		cli.ShowCommandHelpAndExit(c, c.Command.FullName(), 1)
	}

	src, dst := c.Args().Get(0), c.Args().Get(1)
	if dst == "" {
		if ext := filepath.Ext(src); ext == isoExtension {
			return fmt.Errorf("%w: %s", errISOExtension, src)
		}

		dst = strings.TrimSuffix(src, rvz.Extension) + isoExtension
	}

	f, err := os.Open(src) //nolint:gosec // the user chooses which file to read
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}
	defer f.Close()

	r, err := rvz.NewReader(f)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}

	var w io.WriteCloser

	w, err = os.Create(dst) //nolint:gosec // the user chooses which file to write
	if err != nil {
		return fmt.Errorf("creating target: %w", err)
	}

	if c.Bool("verbose") {
		pb := progressbar.DefaultBytes(r.Size())
		w = plumbing.MultiWriteCloser(w, plumbing.NopWriteCloser(pb))
	}

	defer w.Close()

	if _, err = io.Copy(w, r); err != nil {
		return fmt.Errorf("decompressing %s: %w", src, err)
	}

	return nil
}

func main() {
	app := cli.NewApp()

	app.Name = "rvz"
	app.Usage = "RVZ utility"
	app.Version = fmt.Sprintf("%s, commit %s, built at %s", version, commit, date)

	app.Commands = []*cli.Command{
		{
			Name:        "decompress",
			Usage:       "Decompress RVZ image",
			Description: "Decompress RVZ image",
			ArgsUsage:   "SOURCE [TARGET]",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "verbose",
					Aliases: []string{"v"},
					Usage:   "increase verbosity",
				},
			},
			Action: decompress,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
