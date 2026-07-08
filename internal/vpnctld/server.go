// Package vpnctld is the privileged daemon (vpnctld) that owns the netns,
// iptables kill-switch, and tunnel engine process for the whole machine —
// a single system-wide instance, not one per user, matching the reality
// that only one profile is ever active system-wide today (the namespace
// name is fixed). vpnctl (CLI/TUI) talks to it over a Unix socket using
// internal/rpc rather than touching netguard/the engine directly.
//
// This package covers use/down/status/test/ps/kill (request/response) and
// `vpnctl run`'s three modes via Exec (streaming — see exec.go) — see
// DAEMON_MIGRATION.md for what's deliberately not here yet (the TUI's own
// process launchers, systemd/packaging integration).
package vpnctld

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/BeesKnight/vpnctl/internal/engine"
	"github.com/BeesKnight/vpnctl/internal/netguard"
	"github.com/BeesKnight/vpnctl/internal/profile"
	"github.com/BeesKnight/vpnctl/internal/rpc"
)

// connDeadline bounds how long a single request/response exchange may take
// end to end, so a misbehaving or hung client can't tie up a connection
// (and, since handling is one-at-a-time per the mutex, the daemon) forever.
// TestConnectivity's own curl --max-time is 10s, so this leaves headroom.
const connDeadline = 20 * time.Second

// activeState is the daemon's single in-memory record of the currently
// active profile — the direct in-process replacement for netguard's
// file-backed ActiveState (internal/netguard/state.go), which existed only
// because multiple independent CLI processes needed to coordinate through
// a file. A single long-lived daemon process has no such need: a plain
// mutex over this struct is enough, and it can hold the live engine.Handle
// directly instead of having to reconstruct one from a PID recorded on disk.
type activeState struct {
	profile    profile.Profile
	status     netguard.Status // authoritative snapshot; healthCheckLoop keeps ResolvedIP current
	handle     engine.Handle
	healthStop context.CancelFunc

	// activatedByUID/GID identify who ran Activate, from SO_PEERCRED (see
	// peerIdentity) rather than anything self-reported — healthCheckLoop
	// uses this to target a desktop notification at the right session when
	// the tunnel's health flips (see notify.go). Zero when activated by
	// root directly: root has no desktop session of its own to notify.
	activatedByUID, activatedByGID uint32
}

// maxConcurrentConns bounds how many connections vpnctld services at once.
// /run/vpnctl.sock is reachable by every member of the "vpnctl" group, not
// just one trusted caller, so nothing stopped a client from opening
// connections faster than handleConn's connDeadline expires them and
// exhausting the daemon's goroutines/fds before this cap existed. Accept
// itself blocks once the cap is hit (see the semaphore acquire below,
// which happens before the next Accept call) rather than accepting and
// then rejecting — excess connection attempts pile up in the kernel's own
// listen backlog instead of costing vpnctld anything.
const maxConcurrentConns = 64

// Server is vpnctld's connection-handling and state-owning core.
type Server struct {
	mu        sync.Mutex
	ng        netguard.Engine
	active    *activeState           // nil when no profile is active
	processes []netguard.ProcessInfo // everything launched via Exec (see exec.go); the daemon-owned replacement for netguard.ActiveState.Processes/AddProcess/RemoveProcess, which existed to coordinate independent CLI processes through a file

	logger *log.Logger
}

// New creates a Server backed by a real (non-dry-run) Linux network engine.
func New(logger *log.Logger) *Server {
	return NewWithEngine(netguard.NewLinuxEngine(false), logger)
}

// NewWithEngine creates a Server backed by an arbitrary netguard.Engine —
// the seam unit tests use to inject a dry-run engine (netguard.NewLinuxEngine(true)),
// the same pattern internal/netguard's own tests already use to assert on
// generated ip/iptables commands without touching the host.
func NewWithEngine(ng netguard.Engine, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(os.Stderr, "vpnctld: ", log.LstdFlags)
	}
	return &Server{
		ng:     ng,
		logger: logger,
	}
}

// Serve accepts connections on ln, handling each on its own goroutine
// (so a slow TestConnectivity doesn't block an unrelated Status/Ping from
// even being read — only the state-touching work inside each handler is
// serialized, via Server.mu) until ctx is canceled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	connSem := make(chan struct{}, maxConcurrentConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		connSem <- struct{}{}
		go func() {
			defer func() { <-connSem }()
			s.handleConn(conn)
		}()
	}
}

// Shutdown deactivates any active profile (tearing down the namespace/
// kill-switch/engine cleanly, same as a client-initiated Deactivate) so a
// stopped daemon never leaves network state behind for the next start —
// this is what packaging/prerm's whole force_teardown dance existed to
// paper over in the file-based model.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.deactivateLocked(); err != nil {
		s.logger.Printf("shutdown: deactivating: %v", err)
	}
}

// peerIdentity is the real, kernel-verified uid/gid of whoever is on the
// other end of a connection (see peercred_linux.go) — the only thing
// handleExecConn trusts for privilege-drop decisions. Anything in the RPC
// payload itself (rpc.ExecParams.DropUID/DropGID) is client-supplied and
// must never be trusted for that purpose; it can only ever narrow what a
// root peer asks for, never let a non-root peer claim to be someone else.
type peerIdentity struct {
	UID, GID uint32
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(connDeadline))

	uid, gid, err := peerCredentials(conn)
	if err != nil {
		s.logger.Printf("rejecting connection: could not determine peer credentials: %v", err)
		return
	}
	peer := peerIdentity{UID: uid, GID: gid}

	var req rpc.Request
	if err := rpc.ReadMessage(conn, &req); err != nil {
		return // client disconnected or sent garbage; nothing to reply to
	}

	if req.APIVersion != rpc.APIVersion {
		_ = rpc.WriteMessage(conn, &rpc.Response{ID: req.ID, Error: fmt.Sprintf("protocol version mismatch: client=%q daemon=%q — rebuild vpnctl/vpnctld to matching versions", req.APIVersion, rpc.APIVersion)})
		return
	}

	// MethodExec is the one method that doesn't fit request/response: once
	// accepted, this same connection carries a stream of rpc.Frames instead
	// of closing after a single reply — see exec.go. Every other method
	// stays plain request/response, handled by dispatch below.
	if req.Method == rpc.MethodExec {
		s.handleExecConn(conn, req, peer)
		return
	}

	resp := rpc.Response{ID: req.ID}
	if result, err := s.dispatch(req.Method, req.Params, peer); err != nil {
		resp.Error = err.Error()
	} else if data, err := json.Marshal(result); err != nil {
		resp.Error = fmt.Sprintf("marshaling result: %v", err)
	} else {
		resp.Result = data
	}

	_ = rpc.WriteMessage(conn, &resp)
}

func (s *Server) dispatch(method string, params json.RawMessage, peer peerIdentity) (any, error) {
	switch method {
	case rpc.MethodPing:
		return s.handlePing()
	case rpc.MethodActivate:
		var p rpc.ActivateParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("decoding params: %w", err)
		}
		return s.handleActivate(p, peer)
	case rpc.MethodDeactivate:
		return s.handleDeactivate(peer)
	case rpc.MethodStatus:
		return s.handleStatus()
	case rpc.MethodTestConnectivity:
		return s.handleTestConnectivity()
	case rpc.MethodListProcesses:
		return s.handleListProcesses()
	case rpc.MethodKillProcess:
		var p rpc.KillProcessParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("decoding params: %w", err)
		}
		return s.handleKillProcess(p, peer)
	case rpc.MethodGetLogTail:
		var p rpc.GetLogTailParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("decoding params: %w", err)
		}
		return s.handleGetLogTail(p)
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}
