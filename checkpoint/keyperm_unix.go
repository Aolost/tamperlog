//go:build !windows

package checkpoint

import (
	"fmt"
	"os"
)

// checkKeyPermissions refuses key files that grant any permission to group or
// others. The mode comes from the open descriptor (no check/use race).
func checkKeyPermissions(_ *os.File, st os.FileInfo, path string) error {
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %04o", ErrKeyPermissions, path, st.Mode().Perm())
	}
	return nil
}
