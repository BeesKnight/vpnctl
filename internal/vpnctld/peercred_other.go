//go:build !linux

package vpnctld

import (
	"fmt"
	"net"
)

// peerCredentials: no SO_PEERCRED equivalent wired up on non-Linux
// platforms yet (matching internal/netguard/lock_other.go's approach —
// there is no second netguard.Engine implementation on non-Linux for this
// to matter in practice, since vpnctld's whole purpose is Linux network
// namespaces). Every connection is rejected rather than silently trusting
// client-claimed credentials.
func peerCredentials(conn net.Conn) (uid, gid uint32, err error) {
	return 0, 0, fmt.Errorf("peer credential verification is not implemented on this platform")
}
