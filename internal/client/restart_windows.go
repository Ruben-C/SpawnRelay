//go:build windows

package client

import (
	"os"
	"os/exec"
	"syscall"
)

const detachedProcess = 0x00000008

// restart launches the new binary as a detached process with the same
// arguments and exits. The scheduled task that started us does not restart
// exited processes, so the child has to outlive us.
func restart(exe string, args []string) error {
	cmd := exec.Command(exe, args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess}
	cmd.Dir, _ = os.Getwd()
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
