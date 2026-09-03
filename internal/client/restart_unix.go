//go:build !windows

package client

import (
	"os"
	"syscall"
)

// restart replaces the current process image with the new binary. The PID
// is kept, so systemd and launchd see an uninterrupted service. Go opens all
// its descriptors close-on-exec, so the old tunnel connection is dropped.
func restart(exe string, args []string) error {
	argv := append([]string{exe}, args[1:]...)
	return syscall.Exec(exe, argv, os.Environ())
}
