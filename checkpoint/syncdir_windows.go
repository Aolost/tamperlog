//go:build windows

package checkpoint

import (
	"fmt"
	"os"
)

// syncDir on Windows only checks that dir is an existing directory.
//
// Windows has no directory fsync: FlushFileBuffers needs a handle opened for
// writing, which a directory handle cannot be. NTFS journals metadata
// (creations and renames), so a completed rename survives a crash, but it may
// be lost if power fails within the journal's commit interval. SPEC.md §7
// recovery still applies: a lost rename leaves the previous, consistent file.
func syncDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("syncdir: %s is not a directory", dir)
	}
	return nil
}
