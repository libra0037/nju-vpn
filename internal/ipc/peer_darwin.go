package ipc

import (
	"golang.org/x/sys/unix"
)

func verifyPeerFD(fd uintptr, expectedUID uint32) error {
	cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil || cred.Uid != expectedUID {
		return ErrUntrustedPeer
	}
	return nil
}
