// SPDX-License-Identifier: MIT

package main

import (
	"slices"
	"strings"
	"testing"
)

func TestReferencesFollowTheResults(t *testing.T) {
	m := matrix{
		Images: map[string]string{"cbsigma": "{}", "opener": "{}"},
		Rows:   []row{{Reference: "cbsigma"}, {Reference: "opener"}},
	}
	refs, display, err := references(m)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"opener", "cbsigma"}; !slices.Equal(refs, want) {
		t.Fatalf("refs = %v, want %v", refs, want)
	}
	if display["cbsigma"] == "" {
		t.Fatal("cbsigma has no display name")
	}
}

func TestReferencesRejectsAnUnnamedReference(t *testing.T) {
	m := matrix{
		Images: map[string]string{"opener": "{}", "newref": "{}"},
		Rows:   []row{{Reference: "newref"}},
	}
	if _, _, err := references(m); err == nil || !strings.Contains(err.Error(), "newref") {
		t.Fatalf("err = %v, want an error naming newref", err)
	}
}

func TestReferencesRejectsRowsWithoutAnImage(t *testing.T) {
	m := matrix{Rows: []row{{Reference: "opener"}}}
	if _, _, err := references(m); err == nil {
		t.Fatal("no error for a reference without an image")
	}
}
