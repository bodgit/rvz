[![GitHub release](https://img.shields.io/github/v/release/bodgit/rvz)](https://github.com/bodgit/rvz/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/bodgit/rvz/main.yml?branch=main)](https://github.com/bodgit/rvz/actions?query=workflow%3Abuild)
[![Coverage Status](https://coveralls.io/repos/github/bodgit/rvz/badge.svg?branch=main)](https://coveralls.io/github/bodgit/rvz?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/bodgit/rvz)](https://goreportcard.com/report/github.com/bodgit/rvz)
[![GoDoc](https://godoc.org/github.com/bodgit/rvz?status.svg)](https://godoc.org/github.com/bodgit/rvz)
![Go version](https://img.shields.io/badge/Go-1.20-brightgreen.svg)
![Go version](https://img.shields.io/badge/Go-1.19-brightgreen.svg)

# Dolphin RVZ disc images

The [github.com/bodgit/rvz](https://github.com/bodgit/rvz) package reads the [RVZ disc image format](https://github.com/dolphin-emu/dolphin/blob/master/docs/WiaAndRvz.md) used by the [Dolphin emulator](https://dolphin-emu.org).

* Handles all supported compression methods; Zstandard is only marginally slower to read than no compression. Bzip2, LZMA, and LZMA2 are noticeably slower.

How to read a disc image:
```golang
package main

import (
	"io"
	"os"

	"github.com/bodgit/rvz"
)

func main() {
	f, err := os.Open("image.rvz")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	r, err := rvz.NewReader(f)
	if err != nil {
		panic(err)
	}

	w, err := os.Create("image.iso")
	if err != nil {
		panic(err)
	}
	defer w.Close()

	if _, err = io.Copy(w, r); err != nil {
		panic(err)
	}
}
```

## rvz

The `rvz` utility currently allows you to decompress an `.rvz` file back to its original `.iso` format.

A quick demo:

<img src="./decompress.gif">
