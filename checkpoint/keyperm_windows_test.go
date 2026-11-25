//go:build windows

package checkpoint

import (
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
)

// A freshly generated key in a per-user temp dir inherits an owner-only ACL and
// loads; granting read access to Everyone or Users must make it refused.
func TestKeyACLWindows(t *testing.T) {
	for _, group := range []string{"*S-1-1-0", "*S-1-5-32-545"} { // Everyone, Users
		dir := t.TempDir()
		p := filepath.Join(dir, "k.pem")
		if _, err := GenerateKey(p); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrivateKey(p); err != nil {
			t.Fatalf("owner-only key rejected: %v", err)
		}
		if out, err := exec.Command("icacls", p, "/grant", group+":(R)").CombinedOutput(); err != nil {
			t.Fatalf("icacls: %v: %s", err, out)
		}
		if _, err := LoadPrivateKey(p); !errors.Is(err, ErrKeyPermissions) {
			t.Fatalf("key readable by %s accepted: %v", group, err)
		}
	}
}
