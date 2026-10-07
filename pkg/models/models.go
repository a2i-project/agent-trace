package models

import (
	"encoding/json"
	"errors"
	"time"
)

// TrajectoryEntry is a self-reported action from the agent's trajectory log.
type TrajectoryEntry struct {
	Timestamp  time.Time  `json:"timestamp"`
	ActionType ActionType `json:"action_type"`
	Target     string     `json:"target"`
	InputHash  *string    `json:"input_hash,omitempty"`
	OutputHash *string    `json:"output_hash,omitempty"`
	// ExitCode is the process exit code for ProcessExit entries. Nil means
	// not reported (e.g. the action isn't a process exit, or the reporter
	// couldn't determine it).
	ExitCode *int32 `json:"exit_code,omitempty"`
	// RequestHash is "sha256:<hex>" of a NetRequest entry's request body.
	// Nil when the request has no body, or the action isn't a NetRequest.
	RequestHash *string `json:"request_hash,omitempty"`

	// End is when the format says the action finished. Timestamp is then the
	// start of the claim interval and End its end (D12). Nil means the
	// format offers no end timestamp and the entry is a point: the adapter
	// records that degradation instead of inventing a width. Timestamp is a
	// decision time unless the adapter says otherwise (D13), so the interval
	// can include human approval latency and must not be used to bound
	// execution on its own.
	End *time.Time `json:"end,omitempty"`
	// ThreadID names the conversation thread a flattened subagent claim came
	// from (D9). Empty means the main thread, or a format without threads.
	// It is supplied by the agent being verified, so it is a hint for
	// ordering and never a basis for trust.
	ThreadID string `json:"thread_id,omitempty"`
	// BlockID groups claims the format issued in one parallel block (V2).
	// Entries sharing a non-empty BlockID have no order among themselves.
	BlockID string `json:"block_id,omitempty"`
	// Tool names the agent tool the claim came from (for example Claude Code's
	// Edit or Write). It is provenance for the adapter's per-tool declaration of
	// which content fields the format can state, and is supplied by the agent
	// being verified, so it is a hint and never a basis for trust.
	Tool string `json:"tool,omitempty"`
}

// GroundTruthEvent is an independently observed action from the host-level probes.
type GroundTruthEvent struct {
	Timestamp  time.Time  `json:"timestamp"`
	ActionType ActionType `json:"action_type"`
	Target     string     `json:"target"`
	InputHash  *string    `json:"input_hash,omitempty"`
	OutputHash *string    `json:"output_hash,omitempty"`
	// ExitCode is the process exit code for ProcessExit events. Nil means
	// unknown, e.g. the process was killed by an uncaught signal rather than
	// calling exit()/_exit().
	ExitCode *int32 `json:"exit_code,omitempty"`
	// PID is the process that caused the event (its thread group id), as the
	// probe observed it. Zero means the probe did not record it, which is
	// distinct from every real value: pid 0 is the idle task and never causes
	// a userspace event. Attribution walks this up the process tree (V1).
	PID uint32 `json:"pid,omitempty"`
	// PPID is the parent of PID as the probe observed it when the process was
	// created or exec'd. Only the proc probe sets it, since it is the only
	// probe that sees processes start; zero means not recorded. It is what
	// lets the verifier build the tree from events.
	PPID uint32 `json:"ppid,omitempty"`
	// IsTopLevel identifies verification-grade events generated directly by
	// the tracked root process or one of its direct children. A nil value is
	// legacy data and is treated as top-level for backward compatibility.
	//
	// Legacy (to be removed, not tagged Deprecated so staticcheck does not flag
	// the probes and verifier that still use it): a lossy one-bit summary of the structure PID and PPID now
	// carry (V1). Kept only because pkg/verification still reads
	// it until the forest rewrite (Tier 6 step 5) replaces its consumer.
	IsTopLevel *bool `json:"is_top_level,omitempty"`
	// PathIsAmbiguous is true when the probe could only resolve this event
	// to its containing directory, not the specific file within it (a
	// fanotify DFID-only record with no name, produced when the kernel
	// merges events). Matching applies a lenient directory-covers-file
	// fallback only when this is true; an event with a normally-resolved,
	// specific path must match exactly. Absent/false means "this path is
	// exact," which is both the common case and the safe default for any
	// producer that doesn't set it.
	PathIsAmbiguous bool `json:"path_is_ambiguous,omitempty"`
	// RequestHash is "sha256:<hex>" of an observed NetRequest's request
	// body, computed from the plaintext captured pre-encryption. Nil when
	// the request had no body, or the action isn't a NetRequest.
	RequestHash *string `json:"request_hash,omitempty"`
}

func (e *TrajectoryEntry) Validate() error {
	if e.Timestamp.IsZero() {
		return errors.New("timestamp is required")
	}
	if !e.ActionType.IsValid() {
		return errors.New("invalid action type: " + string(e.ActionType))
	}
	if !e.ActionType.IsClaimable() {
		return errors.New("action type cannot be claimed by a trajectory: " + string(e.ActionType))
	}
	if e.Target == "" {
		return errors.New("target is required")
	}
	if e.End != nil && e.End.Before(e.Timestamp) {
		return errors.New("end precedes timestamp")
	}
	return nil
}

func (e *GroundTruthEvent) Validate() error {
	if e.Timestamp.IsZero() {
		return errors.New("timestamp is required")
	}
	if !e.ActionType.IsValid() {
		return errors.New("invalid action type: " + string(e.ActionType))
	}
	if e.Target == "" {
		return errors.New("target is required")
	}
	return nil
}

// Trajectory is an ordered sequence of self-reported entries.
type Trajectory []TrajectoryEntry

// GroundTruth is an ordered sequence of independently observed events.
type GroundTruth []GroundTruthEvent

func ParseTrajectory(data []byte) (Trajectory, error) {
	var t Trajectory
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	for i := range t {
		if err := t[i].Validate(); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func ParseGroundTruth(data []byte) (GroundTruth, error) {
	var g GroundTruth
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, err
	}
	for i := range g {
		if err := g[i].Validate(); err != nil {
			return nil, err
		}
	}
	return g, nil
}

func StringPtr(s string) *string {
	return &s
}
