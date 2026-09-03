//go:build windows

package agent

func ownerOf(path string) (uid, gid int, ok bool) { return 0, 0, false }
