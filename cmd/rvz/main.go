package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/bodgit/rvz"
	"github.com/schollz/progressbar/v3"
	"github.com/urfave/cli/v2"
)

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

	f, err := os.Open(c.Args().First())
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := rvz.NewReader(f)
	if err != nil {
		return err
	}

	var w io.Writer

	if c.NArg() >= 2 {
		w, err = os.Create(c.Args().Get(1))
		if err != nil {
			return err
		}
		defer w.(io.Closer).Close() //nolint:forcetypeassert
	} else {
		w = os.Stdout
	}

	if c.Bool("verbose") {
		pb := progressbar.DefaultBytes(r.Size())
		w = io.MultiWriter(w, pb)
	}

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
