//go:build windows

package main

import (
	"os/exec"
	"testing"
)

// Windows has no mode bits; loosen the key by granting Everyone read access.
func loosenKey(t *testing.T, path string) {
	if out, err := exec.Command("icacls", path, "/grant", "*S-1-1-0:(R)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
}

func tightenKey(t *testing.T, path string) {
	if out, err := exec.Command("icacls", path, "/remove:g", "*S-1-1-0").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
}
