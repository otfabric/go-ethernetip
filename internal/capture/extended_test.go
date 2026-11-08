// SPDX-License-Identifier: MIT

//go:build captures

package capture

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// The raw files of the excerpts (`make captures-fetch`) hold what
// Wireshark 4.6 decodes, and each committed excerpt is what Excerpts
// keeps of its raw file. ENIP_CIP-CM frame 5 is a 1460-octet
// retransmission of the stream before frame 1: 14 Forward_Open requests
// (the last the octets of frame 1) and 60 octets of a 15th, which tshark
// does not dissect (it counts 8).
func TestCachedCapturesMatchWireshark(t *testing.T) {
	want := map[string]struct{ explicit, convs, dropped int }{
		"controllogix-download":     {346, 2, 0},
		"controllogix-factorytalk":  {272, 1, 0},
		"enip-cip-cm":               {21, 3, 1},
		"ethernetip-cip-cloudshark": {8799, 4, 0},
	}
	m, err := ReadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range m.Files {
		if f.Storage != "excerpt" {
			continue
		}
		w := want[f.ID]
		convs, err := ReadFile(filepath.Join(dir, f.CachePath()))
		if err != nil {
			t.Fatalf("%s: %v (run make captures-fetch)", f.ID, err)
		}
		n := Count(convs, func(Conversation, Message) bool { return true })
		dropped := 0
		for _, c := range convs {
			dropped += c.Dropped
		}
		if n != w.explicit || len(convs) != w.convs || dropped != w.dropped {
			t.Errorf("%s: %d messages, %d conversations, %d dropped; want %+v", f.ID, n, len(convs), dropped, w)
		}
		e, err := ReadExcerpt(filepath.Join(dir, f.Local))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := json.Marshal(Excerpts(convs, f.MaxPerKind))
		have, _ := json.Marshal(e.Conversations)
		if string(got) != string(have) {
			t.Errorf("%s: the excerpt is not what its raw file gives (run make captures-excerpts)", f.ID)
		}
	}
}
