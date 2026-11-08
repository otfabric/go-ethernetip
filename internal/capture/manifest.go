// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Manifest is testdata/captures/manifest.json: the sources of the recorded
// traffic and, per file, where it came from, its checksum and its evidence
// class.
type Manifest struct {
	Schema   int               `json:"schema"`
	Acquired string            `json:"acquired"`
	Classes  map[string]string `json:"classes"`
	Sources  []Source          `json:"sources"`
	Files    []File            `json:"files"`
	// Examined lists files of the sources that are not here, and why.
	Examined []Examined `json:"examined"`
}

// Examined is a file of a source that is not in the corpus.
type Examined struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Why    string `json:"why"`
}

// Source is one origin of captures.
type Source struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	Revision       string `json:"revision"`
	Licence        string `json:"licence"`
	Redistribution string `json:"redistribution"`
}

// File is one capture file.
type File struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	// Name is the file's name here, <client-or-peer>_<device>_<operation>
	// with the original extension (testdata/captures/README.md).
	Name         string `json:"name"`
	OriginalName string `json:"original_name"`
	Path         string `json:"path"` // in the source
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Recorded     string `json:"recorded"`
	// Class is the evidence class (A to D, see Manifest.Classes).
	Class string `json:"class"`
	// Storage is "raw" (committed byte-identical at Local) or "excerpt"
	// (Local is the excerpt; the raw file is fetched into the cache).
	Storage     string   `json:"storage"`
	Local       string   `json:"local"`
	MaxPerKind  int      `json:"maxPerKind,omitempty"`
	Devices     []string `json:"devices"`
	Peers       []string `json:"peers"`
	Operations  []string `json:"operations"`
	Limitations string   `json:"limitations"`
}

// ReadManifest reads manifest.json from the captures directory dir.
func ReadManifest(dir string) (Manifest, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile("manifest.json")
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("capture: manifest: %w", err)
	}
	return m, nil
}

// Recording is one file of the corpus, read into conversations.
type Recording struct {
	File          File
	Conversations []Conversation
}

// Load reads every capture of the corpus in the captures directory dir.
func Load(dir string) ([]Recording, error) {
	m, err := ReadManifest(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Recording, 0, len(m.Files))
	for _, f := range m.Files {
		convs, err := ReadFile(filepath.Join(dir, f.Local))
		if err != nil {
			return nil, fmt.Errorf("capture: %s: %w", f.ID, err)
		}
		out = append(out, Recording{File: f, Conversations: convs})
	}
	return out, nil
}

// Get returns the recording of the file with manifest ID id.
func Get(recs []Recording, id string) (Recording, bool) {
	for _, r := range recs {
		if r.File.ID == id {
			return r, true
		}
	}
	return Recording{}, false
}

// Frame returns the message that frame n completed, and its conversation.
func (r Recording) Frame(n int) (Conversation, Message, bool) {
	for _, c := range r.Conversations {
		for _, m := range c.Messages {
			if m.Frame == n {
				return c, m, true
			}
		}
	}
	return Conversation{}, Message{}, false
}

// Exchange returns the exchange whose request frame n completed.
func (r Recording) Exchange(n int) (Exchange, bool) {
	for _, c := range r.Conversations {
		if c.Transport != TCP {
			continue
		}
		ex, _ := Exchanges(c)
		for _, e := range ex {
			if e.Request.Frame == n {
				return e, true
			}
		}
	}
	return Exchange{}, false
}

var (
	cacheMu sync.Mutex
	cache   = map[string][]Recording{}
)

// Cached is Load, read once per directory and process: the tests of a
// package share the corpus instead of reading its 30 MB for each test. The
// recordings must not be modified.
func Cached(dir string) ([]Recording, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if r, ok := cache[dir]; ok {
		return r, nil
	}
	r, err := Load(dir)
	if err == nil {
		cache[dir] = r
	}
	return r, err
}
