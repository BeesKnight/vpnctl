//go:build linux

package vpnctld

import (
	"fmt"
	"net"
	"syscall"
)

// peerCredentials returns the real uid/gid of the process on the other end
// of a Unix socket connection, via SO_PEERCRED — the kernel fills this in
// from the connecting process's actual credentials at connect(2) time, so
// unlike anything in an RPC payload it cannot be spoofed by the client.
// This is what lets handleExecConn (exec.go) refuse to trust a
// client-claimed DropUID/DropGID for a non-root peer: Exec forces the
// privilege drop to whatever this function reports instead of whatever the
// client asked for. Group membership on /run/vpnctl.sock was only ever
// meant to gate reaching the daemon at all, not to grant root code
// execution to anyone who can open() the socket — see DAEMON_MIGRATION.md.
func peerCredentials(conn net.Conn) (uid, gid uint32, err error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, fmt.Errorf("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *syscall.Ucred
	var sockErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); ctrlErr != nil {
		return 0, 0, ctrlErr
	}
	if sockErr != nil {
		return 0, 0, sockErr
	}
	return uint32(cred.Uid), uint32(cred.Gid), nil
}
