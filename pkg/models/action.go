package models

type ActionType string

const (
	FileOpen   ActionType = "file_open"
	FileRead   ActionType = "file_read"
	FileWrite  ActionType = "file_write"
	FileClose  ActionType = "file_close"
	FileRename ActionType = "file_rename"
	FileDelete ActionType = "file_delete"
	NetRequest ActionType = "net_request"
	NetDNS     ActionType = "net_dns"
	NetConnect ActionType = "net_connect"
	// NetBind and NetListen are listener capability evidence. They exist in
	// ground truth only: no trajectory format records them, so a trajectory
	// cannot claim them (see IsClaimable) and the verifier never aligns them.
	NetBind   ActionType = "net_bind"
	NetListen ActionType = "net_listen"
	// NetUnixConnect is a connect() to an AF_UNIX socket, the usual channel
	// for delegating work to a daemon outside the tracked tree (the Docker
	// socket, a systemd private socket). Ground truth only, like NetBind.
	NetUnixConnect ActionType = "net_unix_connect"
	// ProcessFork records that PPID created PID. It is structure, not an
	// action: it exists so the verifier can place processes that never exec in
	// the tree. Ground truth only, never claimable, and not capability
	// evidence either (see IsStructural).
	ProcessFork ActionType = "process_fork"
	ProcessExec ActionType = "process_exec"
	ProcessExit ActionType = "process_exit"
	GitCommit   ActionType = "git_commit"
)

var validActionTypes = map[ActionType]bool{
	FileOpen:       true,
	FileRead:       true,
	FileWrite:      true,
	FileClose:      true,
	FileRename:     true,
	FileDelete:     true,
	NetRequest:     true,
	NetDNS:         true,
	NetConnect:     true,
	NetBind:        true,
	NetListen:      true,
	NetUnixConnect: true,
	ProcessFork:    true,
	ProcessExec:    true,
	ProcessExit:    true,
	GitCommit:      true,
}

func (a ActionType) IsValid() bool {
	return validActionTypes[a]
}

// unclaimableActionTypes are observed but never reportable by an agent. They
// are valid in ground truth and invalid in a trajectory.
var unclaimableActionTypes = map[ActionType]bool{
	NetBind:        true,
	NetListen:      true,
	NetUnixConnect: true,
	ProcessFork:    true,
}

// IsStructural reports whether an event describes the shape of the process
// tree rather than something the agent did. Structural events are consumed
// by the tree builder and are neither aligned nor counted as capability.
func (a ActionType) IsStructural() bool {
	return a == ProcessFork
}

// IsClaimable reports whether a trajectory may claim this action type.
func (a ActionType) IsClaimable() bool {
	return validActionTypes[a] && !unclaimableActionTypes[a]
}
