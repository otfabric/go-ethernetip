// SPDX-License-Identifier: MIT

// Command capturecorpus maintains testdata/captures (see its README):
//
//	capturecorpus fetch     download the raw files of excerpts into the
//	                        cache (testdata/captures/.cache), checking their
//	                        SHA256 and size, and check the committed raw files
//	capturecorpus excerpts  write the excerpts from the cached raw files
//	capturecorpus check     fail if an excerpt differs from what excerpts
//	                        would write
//
// fetch is the only step that uses the network.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/otfabric/go-ethernetip/internal/capture"
)

func main() {
	dir := flag.String("dir", "testdata/captures", "captures directory")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: capturecorpus [-dir d] fetch|excerpts|check")
		os.Exit(2)
	}
	m, err := capture.ReadManifest(*dir)
	if err == nil {
		switch flag.Arg(0) {
		case "fetch":
			err = fetch(*dir, m)
		case "excerpts":
			err = excerpts(*dir, m, false)
		case "check":
			err = excerpts(*dir, m, true)
		default:
			err = fmt.Errorf("unknown command %q", flag.Arg(0))
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "capturecorpus:", err)
		os.Exit(1)
	}
}

func fetch(dir string, m capture.Manifest) error {
	for _, f := range m.Files {
		switch f.Storage {
		case "raw":
			if err := verify(dir, f.Local, f); err != nil {
				return err
			}
		case "excerpt":
			if verify(dir, f.CachePath(), f) == nil {
				continue
			}
			if err := download(f.URL, dir, f.CachePath()); err != nil {
				return fmt.Errorf("%s: %w", f.ID, err)
			}
			if err := verify(dir, f.CachePath(), f); err != nil {
				return err
			}
			fmt.Println("fetched", f.CachePath())
		default:
			return fmt.Errorf("%s: storage %q", f.ID, f.Storage)
		}
	}
	return nil
}

func download(url, dir, rel string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	return writeFile(dir, rel, b)
}

// readFile and writeFile access files below the captures directory only.
func readFile(dir, rel string) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(rel)
}

func writeFile(dir, rel string, b []byte) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirAll(filepath.Dir(rel), 0o750); err != nil {
		return err
	}
	return root.WriteFile(rel, b, 0o600)
}

func verify(dir, rel string, f capture.File) error {
	b, err := readFile(dir, rel)
	if err != nil {
		return fmt.Errorf("%s: %w", f.ID, err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != f.SHA256 || int64(len(b)) != f.Size {
		return fmt.Errorf("%s: %s has SHA256 %s and %d octets, want %s and %d", f.ID, rel, got, len(b), f.SHA256, f.Size)
	}
	return nil
}

var errStale = errors.New("excerpt differs from its raw file; run make captures-excerpts")

func excerpts(dir string, m capture.Manifest, check bool) error {
	for _, f := range m.Files {
		if f.Storage != "excerpt" {
			continue
		}
		raw := filepath.Join(dir, f.CachePath())
		if err := verify(dir, f.CachePath(), f); err != nil {
			return fmt.Errorf("%w (run make captures-fetch)", err)
		}
		convs, err := capture.ReadFile(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", f.ID, err)
		}
		note := "Excerpt; raw file not redistributed. The EtherNet/IP messages of " + filepath.Base(f.Path) +
			" (testdata/captures/manifest.json, id " + f.ID + ") without link, IP and TCP headers; repeated exchanges left out"
		if f.MaxPerKind > 0 {
			note += fmt.Sprintf(", at most %d exchanges per request shape and conversation", f.MaxPerKind)
		}
		e := capture.Excerpt{
			Source: f.Source, File: filepath.Base(f.Path), SHA256: f.SHA256,
			Note:          note + ". Written by internal/cmd/capturecorpus.",
			Conversations: capture.Excerpts(convs, f.MaxPerKind),
		}
		b, err := json.MarshalIndent(e, "", " ")
		if err != nil {
			return err
		}
		b = append(b, '\n')
		if check {
			old, err := readFile(dir, f.Local)
			if err != nil {
				return err
			}
			if !bytes.Equal(old, b) {
				return fmt.Errorf("%s: %w", f.Local, errStale)
			}
			continue
		}
		if err := writeFile(dir, f.Local, b); err != nil {
			return err
		}
		fmt.Println("wrote", f.Local)
	}
	return nil
}
