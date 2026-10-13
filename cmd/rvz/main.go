// Command rvz compresses ISO disc images to RVZ disc images and back again.
package main

import (
	"context"
	"encoding/hex"
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

var (
	errISOExtension     = errors.New("source file already has " + isoExtension + " extension")
	errRVZExtension     = errors.New("source file already has " + rvz.Extension + " extension")
	errUnknownAlgorithm = errors.New("unknown compression algorithm")
	errBadKey           = errors.New("key must be 32 hexadecimal digits")
)

// keyFlags are the flags for each Wii common key, in the order of their
// index.
//
//nolint:gochecknoglobals
var keyFlags = []struct {
	name, env, usage string
}{
	{"common-key", "RVZ_COMMON_KEY", "Wii common key"},
	{"korean-key", "RVZ_KOREAN_KEY", "Wii Korean common key"},
	{"vwii-key", "RVZ_VWII_KEY", "vWii common key"},
}

//nolint:gochecknoglobals
var methods = map[string]uint32{
	"none": rvz.MethodNone,
	"zstd": rvz.MethodZstandard,
}

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

func compress(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		cli.ShowCommandHelpAndExit(ctx, cmd.Root(), cmd.Name, 1)
	}

	src, dst := cmd.Args().Get(0), cmd.Args().Get(1)
	if dst == "" {
		if ext := filepath.Ext(src); ext == rvz.Extension {
			return fmt.Errorf("%w: %s", errRVZExtension, src)
		}

		dst = strings.TrimSuffix(src, isoExtension) + rvz.Extension
	}

	method, ok := methods[cmd.String("compression")]
	if !ok {
		return fmt.Errorf("%w: %s", errUnknownAlgorithm, cmd.String("compression"))
	}

	opts := []rvz.Option{
		rvz.WithCompression(method, cmd.Int("level")),
		rvz.WithChunkSize(cmd.Int("chunk-size")),
	}

	for index, flag := range keyFlags {
		s := cmd.String(flag.name)
		if s == "" {
			continue
		}

		key, err := parseKey(s)
		if err != nil {
			return fmt.Errorf("%w: --%s", err, flag.name)
		}

		opts = append(opts, rvz.WithCommonKey(index, key))
	}

	return compressFile(src, dst, cmd.Bool("verbose"), opts...)
}

// progressReaderAt writes everything read through it to w.
type progressReaderAt struct {
	io.ReaderAt

	w io.Writer
}

func (p *progressReaderAt) ReadAt(b []byte, off int64) (int, error) {
	n, err := p.ReaderAt.ReadAt(b, off)
	_, _ = p.w.Write(b[:n])

	return n, err //nolint:wrapcheck // must be returned as is
}

func compressFile(src, dst string, verbose bool, opts ...rvz.Option) (err error) {
	f, err := os.Open(filepath.Clean(src))
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}

	defer func() {
		_ = f.Close()
	}()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}

	var ra io.ReaderAt = f

	if verbose {
		ra = &progressReaderAt{ReaderAt: f, w: progressbar.DefaultBytes(fi.Size())}
	}

	w, err := os.Create(filepath.Clean(dst))
	if err != nil {
		return fmt.Errorf("creating target: %w", err)
	}

	// A failure to close the target may mean it's incomplete
	defer func() {
		if cerr := w.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing target: %w", cerr)
		}
	}()

	if err = rvz.Compress(w, ra, fi.Size(), opts...); err != nil {
		return fmt.Errorf("compressing %s: %w", src, err)
	}

	return nil
}

func parseKey(s string) ([16]byte, error) {
	var key [16]byte

	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(key) {
		return key, errBadKey
	}

	copy(key[:], b)

	return key, nil
}

// keyFlagsList returns a flag for each Wii common key, which can also be set
// from the environment.
func keyFlagsList() []cli.Flag {
	flags := make([]cli.Flag, 0, len(keyFlags))

	for _, flag := range keyFlags {
		flags = append(flags, &cli.StringFlag{
			Name:    flag.name,
			Usage:   flag.usage + " as hexadecimal, needed to compress Wii partitions",
			Sources: cli.EnvVars(flag.env),
		})
	}

	return flags
}

func main() {
	cmd := &cli.Command{
		Name:    "rvz",
		Usage:   "RVZ utility",
		Version: fmt.Sprintf("%s, commit %s, built at %s", version, commit, date),
		Commands: []*cli.Command{
			{
				Name:        "compress",
				Usage:       "Compress ISO image",
				Description: "Compress ISO image",
				ArgsUsage:   "SOURCE [TARGET]",
				Flags: append([]cli.Flag{
					&cli.StringFlag{
						Name:    "compression",
						Aliases: []string{"c"},
						Usage:   "compression algorithm, either zstd or none",
						Value:   "zstd",
					},
					&cli.IntFlag{
						Name:    "level",
						Aliases: []string{"l"},
						Usage:   "compression level, from 1 to 22",
						Value:   rvz.DefaultLevel,
					},
					&cli.IntFlag{
						Name:    "chunk-size",
						Aliases: []string{"b"},
						Usage:   "chunk size in bytes, a power of two from 32 KiB to 2 MiB",
						Value:   rvz.DefaultChunkSize,
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "increase verbosity",
					},
				}, keyFlagsList()...),
				Action: compress,
			},
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
