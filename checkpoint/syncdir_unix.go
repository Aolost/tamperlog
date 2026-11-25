//go:build !windows

package checkpoint

import "os"

// syncDir fsyncs a directory so that renames and creations in it are durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
