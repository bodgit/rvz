package main

import (
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
			return fmt.Errorf("source file %s already has %s extension", src, isoExtension)
		}

		dst = strings.TrimSuffix(src, rvz.Extension) + isoExtension
	}

	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := rvz.NewReader(f)
	if err != nil {
		return err
	}

	var w io.WriteCloser

	w, err = os.Create(dst)
	if err != nil {
		return err
	}

	if c.Bool("verbose") {
		pb := progressbar.DefaultBytes(r.Size())
		w = plumbing.MultiWriteCloser(w, plumbing.NopWriteCloser(pb))
	}

	defer w.Close()

	_, err = io.Copy(w, r)

	return err
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
