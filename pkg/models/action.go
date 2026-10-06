package models

type ActionType string

const (
	FileOpen    ActionType = "file_open"
	FileRead    ActionType = "file_read"
	FileWrite   ActionType = "file_write"
	FileClose   ActionType = "file_close"
	FileRename  ActionType = "file_rename"
	FileDelete  ActionType = "file_delete"
	NetRequest  ActionType = "net_request"
	NetDNS      ActionType = "net_dns"
	NetConnect  ActionType = "net_connect"
	// NetBind and NetListen are listener capability evidence. They exist in
	// ground truth only: no trajectory format records them, so a trajectory
	// cannot claim them (see IsClaimable) and the verifier never aligns them.
	NetBind     ActionType = "net_bind"
	NetListen   ActionType = "net_listen"
	ProcessExec ActionType = "process_exec"
	ProcessExit ActionType = "process_exit"
	GitCommit   ActionType = "git_commit"
)

var validActionTypes = map[ActionType]bool{
	FileOpen:    true,
	FileRead:    true,
	FileWrite:   true,
	FileClose:   true,
	FileRename:  true,
	FileDelete:  true,
	NetRequest:  true,
	NetDNS:      true,
	NetConnect:  true,
	NetBind:     true,
	NetListen:   true,
	ProcessExec: true,
	ProcessExit: true,
	GitCommit:   true,
}

func (a ActionType) IsValid() bool {
	return validActionTypes[a]
}

// unclaimableActionTypes are observed but never reportable by an agent. They
// are valid in ground truth and invalid in a trajectory.
var unclaimableActionTypes = map[ActionType]bool{
	NetBind:   true,
	NetListen: true,
}

// IsClaimable reports whether a trajectory may claim this action type.
func (a ActionType) IsClaimable() bool {
	return validActionTypes[a] && !unclaimableActionTypes[a]
}
