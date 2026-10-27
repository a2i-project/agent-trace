package models

import (
	"encoding/json"
	"errors"
	"fmt"
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
	// ImpliedBy marks a harness-implied claim (V-33): an action the harness
	// may or may not perform on its own because of a call, here a read of the
	// file a Bash command read, with the claimed command it follows. Only an
	// adapter's derivation sets it, never the agent: it has no JSON form, so
	// no trajectory read from JSON can carry it, and ParseTrajectory rejects
	// input that names it. The verifier lets such a claim pair only with an
	// open of exactly its target that the named command's subtree opened
	// first, and costs nothing when it stays unpaired. Empty for every
	// claim of the agent.
	ImpliedBy string `json:"-"`
	// ImpliedBefore marks a harness-implied claim whose action comes before
	// the command it names reads the same file, as Claude Code's Grep opens
	// the file it searches and hands it to its ripgrep (I-69). The verifier
	// then lets it pair only with an open no later than one beneath the
	// command (V-48). False for a read that follows its command (I-46).
	// Ignored without ImpliedBy; like it, it has no JSON form.
	ImpliedBefore bool `json:"-"`
}

// impliedByKey and impliedBeforeKey are the names the harness-implied
// markers would have in a trajectory read from JSON. ParseTrajectory refuses
// them (V-33, V-48).
const (
	impliedByKey     = "implied_by"
	impliedBeforeKey = "implied_before"
)

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
	// PathIsAmbiguous is true when the probe could only resolve this event
	// to its containing directory, not the specific file within it (a
	// fanotify DFID-only record with no name, produced when the kernel
	// merges events). Matching applies a lenient directory-covers-file
	// fallback only when this is true; an event with a normally-resolved,
	// specific path must match exactly. Absent/false means "this path is
	// exact," which is both the common case and the safe default for any
	// producer that doesn't set it.
	PathIsAmbiguous bool `json:"path_is_ambiguous,omitempty"`
	// TargetTruncated is true when the probe could not record the whole
	// target: the proc probe keeps at most 64 arguments and 128 KiB of a
	// command line, and 256 bytes of the program path. The target is then a
	// prefix of the real one, and the verifier pairs it by prefix and marks
	// the pair unverified rather than mismatched (P-19).
	TargetTruncated bool `json:"target_truncated,omitempty"`
	// RequestHash is "sha256:<hex>" of an observed NetRequest's request
	// body, computed from the plaintext captured pre-encryption. Nil when
	// the request had no body, or the action isn't a NetRequest.
	RequestHash *string `json:"request_hash,omitempty"`
	// Response is the attestation record of a NetResponse event (N-29).
	// Nil on every other action type.
	Response *ResponseAttestation `json:"response,omitempty"`
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
	// A harness-implied claim comes only from an adapter's own derivation; a
	// trajectory that names the marker is refused rather than read without
	// it, so nobody takes a dropped marker for an honoured one (V-33).
	var keys []map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, err
	}
	for i, k := range keys {
		for _, key := range []string{impliedByKey, impliedBeforeKey} {
			if _, ok := k[key]; ok {
				return nil, fmt.Errorf("entry %d: %s is set only by an adapter, never read from a trajectory", i, key)
			}
		}
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
