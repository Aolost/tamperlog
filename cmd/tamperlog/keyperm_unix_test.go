//go:build !windows

package main

import (
	"os"
	"testing"
)

func loosenKey(t *testing.T, path string) {
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

func tightenKey(t *testing.T, path string) {
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}
