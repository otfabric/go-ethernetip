// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"testing"
)

// TestCheck fails when the committed sample is not what the generator
// writes.
func TestCheck(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("../../.."); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := run(true); err != nil {
		t.Fatal(err)
	}
}
