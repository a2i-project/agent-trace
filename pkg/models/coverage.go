package models

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// CoverageSchema is the version of the coverage record this build writes and
// accepts. A file with another version is rejected rather than guessed at.
const CoverageSchema = 1

// Content states for ProbeCoverage.Content (net probe only).
const (
	ContentActive       = "active"
	ContentIdentityOnly = "identity_only"
	ContentAttachFailed = "attach_failed"
)

// ProbeCoverage holds one probe's raw loss counters for a capture run. It
// stores counters only. Whether a run is complete is a judgement the verifier
// makes (see pkg/verification.Assess), not something the probe asserts.
type ProbeCoverage struct {
	// Ran is false for a probe that was not started. Absence of its events
	// then says nothing about whether the agent performed such actions.
	Ran bool `json:"ran"`
	// RingbufDrops counts records the kernel ring buffer discarded because it
	// was full. Those events never reached userspace.
	RingbufDrops uint64 `json:"ringbuf_drops"`
	// UntrackedChildren counts descendants of the tracked tree that the
	// kernel could not add to its tracked_pids map because it was full. Each
	// is invisible to the probe along with everything it forks afterwards, so
	// this is event loss. One increment can stand for a whole subtree: a
	// lower bound, meaningful only as zero versus non-zero.
	UntrackedChildren uint64 `json:"untracked_children"`
	// StateMapFull counts records lost because a per-process (proc: exit
	// records) or per-connection (net: connections) kernel state map was
	// full, so the entry could not be stored. Event loss. A lower bound.
	StateMapFull uint64 `json:"state_map_full"`
	// ChannelDrops counts events userspace discarded because the Go events
	// channel was full.
	ChannelDrops uint64 `json:"channel_drops"`
	// FaultedReads counts SSL_write calls whose plaintext could not be read.
	// A content gap, not an event loss. Net probe only.
	FaultedReads uint64 `json:"faulted_reads,omitempty"`
	// QueueOverflow reports a kernel fanotify queue overflow, meaning some
	// events were lost. Filesystem probe only.
	QueueOverflow bool `json:"queue_overflow,omitempty"`
	// Content is one of the Content* constants. Net probe only.
	Content string `json:"content,omitempty"`
}

// Coverage is the per-probe loss record that travels with a ground truth file.
type Coverage struct {
	Schema int                      `json:"schema"`
	Probes map[string]ProbeCoverage `json:"probes"`
}

// GroundTruthFile is the on-disk form of a capture: the events plus the record
// of what the capture may have lost. A nil Coverage means unknown, which is
// not the same as complete.
type GroundTruthFile struct {
	Events   GroundTruth `json:"events"`
	Coverage *Coverage   `json:"coverage"`
	// RootPID is the agent process the capture was rooted at, the root of the
	// process forest the verifier builds (V1). Zero means the capture had
	// no root (legacy file, or host-wide recording), so no tree can be built
	// and the verifier cannot attribute events.
	RootPID uint32 `json:"root_pid,omitempty"`
	// Workspace is the absolute directory the capture watched. A harness
	// baseline names it with a placeholder, so a baseline measured in one
	// directory applies to a run in another. Empty means unknown.
	Workspace string `json:"workspace,omitempty"`
}

// ParseGroundTruthFile reads a ground truth file in either form: the current
// object with events and coverage, or the legacy bare array of events. A
// legacy array, or an object with no coverage, yields a nil Coverage.
//
// ParseGroundTruth, and a bare json.Unmarshal into GroundTruth, reject the
// object form on purpose, so a caller that ignores coverage fails loudly and
// does not silently drop it.
func ParseGroundTruthFile(data []byte) (GroundTruthFile, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return GroundTruthFile{}, fmt.Errorf("ground truth file is empty")
	}

	var f GroundTruthFile
	if trimmed[0] == '[' {
		events, err := ParseGroundTruth(trimmed)
		if err != nil {
			return GroundTruthFile{}, err
		}
		f.Events = events
		return f, nil
	}

	if err := json.Unmarshal(trimmed, &f); err != nil {
		return GroundTruthFile{}, err
	}
	for i := range f.Events {
		if err := f.Events[i].Validate(); err != nil {
			return GroundTruthFile{}, err
		}
	}
	if f.Coverage != nil && f.Coverage.Schema != CoverageSchema {
		return GroundTruthFile{}, fmt.Errorf("unsupported coverage schema %d (this build reads %d)", f.Coverage.Schema, CoverageSchema)
	}
	return f, nil
}
