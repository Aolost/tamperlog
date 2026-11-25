//go:build windows

package checkpoint

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// checkKeyPermissions on Windows inspects the file's DACL instead of Unix mode
// bits (which Go synthesises from the read-only attribute and are meaningless
// here). The key is refused when the DACL is missing (NULL DACL = everyone has
// full access) or when it grants any access to the well-known broad groups
// Everyone (S-1-1-0), Authenticated Users (S-1-5-11) or Users (S-1-5-32-545).
//
// This is a conservative approximation of "0600": it does not prove that only
// the owner can read the key (another named user could still be granted
// access), but it catches the common misconfigurations.
func checkKeyPermissions(f *os.File, _ os.FileInfo, path string) error {
	var (
		dacl *acl
		sd   uintptr
	)
	r, _, _ := procGetSecurityInfo.Call(
		f.Fd(), seFileObject, daclSecurityInformation,
		0, 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&sd)))
	if r != 0 {
		return fmt.Errorf("%w: %s: cannot read its access control list (error %d)", ErrKeyPermissions, path, r)
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	if dacl == nil {
		return fmt.Errorf("%w: %s has no access control list (everyone has access)", ErrKeyPermissions, path)
	}
	broad := make([]*syscall.SID, 0, len(broadSIDs))
	for _, s := range broadSIDs {
		sid, err := syscall.StringToSid(s)
		if err != nil {
			return err
		}
		broad = append(broad, sid)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *accessAllowedAce
		if r, _, _ := procGetAce.Call(uintptr(unsafe.Pointer(dacl)), uintptr(i), uintptr(unsafe.Pointer(&ace))); r == 0 {
			return fmt.Errorf("%w: %s: cannot read access control entry %d", ErrKeyPermissions, path, i)
		}
		if ace.Header.AceType != accessAllowedAceType || ace.Mask == 0 {
			continue
		}
		sid := (*syscall.SID)(unsafe.Pointer(&ace.SidStart))
		for j, b := range broad {
			if equalSid(sid, b) {
				return fmt.Errorf("%w: %s grants access to %s", ErrKeyPermissions, path, broadNames[j])
			}
		}
	}
	return nil
}

var (
	broadSIDs  = []string{"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}
	broadNames = []string{"Everyone", "Authenticated Users", "Users"}

	modadvapi32         = syscall.NewLazyDLL("advapi32.dll")
	procGetSecurityInfo = modadvapi32.NewProc("GetSecurityInfo")
	procGetAce          = modadvapi32.NewProc("GetAce")
	procEqualSid        = modadvapi32.NewProc("EqualSid")
)

const (
	seFileObject            = 1
	daclSecurityInformation = 0x4
	accessAllowedAceType    = 0
)

type acl struct {
	AclRevision uint8
	Sbz1        uint8
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

type aceHeader struct {
	AceType  uint8
	AceFlags uint8
	AceSize  uint16
}

type accessAllowedAce struct {
	Header   aceHeader
	Mask     uint32
	SidStart uint32
}

func equalSid(a, b *syscall.SID) bool {
	r, _, _ := procEqualSid.Call(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(b)))
	return r != 0
}
