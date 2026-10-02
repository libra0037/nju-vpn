package ipc

import (
	"golang.org/x/sys/unix"
)

func verifyPeerFD(fd uintptr, expectedUID uint32) error {
	cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || cred.Uid != expectedUID {
		return ErrUntrustedPeer
	}
	return nil
}
