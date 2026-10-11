// Command rvz decompresses RVZ disc images to ISO images.
package main

import (
	"context"
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
	"github.com/urfave/cli/v3"
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
		Name:        "version",
		Aliases:     []string{"V"},
		Usage:       "print the version",
		HideDefault: true,
		Local:       true,
	}
}

func decompress(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		cli.ShowCommandHelpAndExit(ctx, cmd.Root(), cmd.Name, 1)
	}

	src, dst := cmd.Args().Get(0), cmd.Args().Get(1)
	if dst == "" {
		if ext := filepath.Ext(src); ext == isoExtension {
			return fmt.Errorf("%w: %s", errISOExtension, src)
		}

		dst = strings.TrimSuffix(src, rvz.Extension) + isoExtension
	}

	return decompressFile(src, dst, cmd.Bool("verbose"))
}

func decompressFile(src, dst string, verbose bool) (err error) {
	f, err := os.Open(filepath.Clean(src))
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}

	defer func() {
		_ = f.Close()
	}()

	r, err := rvz.NewReader(f)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}

	var w io.WriteCloser

	w, err = os.Create(filepath.Clean(dst))
	if err != nil {
		return fmt.Errorf("creating target: %w", err)
	}

	if verbose {
		pb := progressbar.DefaultBytes(r.Size())
		w = plumbing.MultiWriteCloser(w, plumbing.NopWriteCloser(pb))
	}

	// A failure to close the target may mean it's incomplete
	defer func() {
		if cerr := w.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing target: %w", cerr)
		}
	}()

	if _, err = io.Copy(w, r); err != nil {
		return fmt.Errorf("decompressing %s: %w", src, err)
	}

	return nil
}

func main() {
	cmd := &cli.Command{
		Name:    "rvz",
		Usage:   "RVZ utility",
		Version: fmt.Sprintf("%s, commit %s, built at %s", version, commit, date),
		Commands: []*cli.Command{
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
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
