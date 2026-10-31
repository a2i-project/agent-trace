package main

import (
	"regexp"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The causes of an INCONCLUSIVE outcome, read from the verdict's Reasons
// (protocol section 4, H3c). The list order is the protocol's fixed
// precedence: a run with several causes is counted under each (multi-cause)
// and under the first that applies (primary).
const (
	CauseNoRoot          = "no_root_pid"
	CauseTooLarge        = "too_large"
	CauseEventLoss       = "event_loss"
	CauseIOUring         = "io_uring"
	CauseVersion         = "version_not_configured"
	CauseUnverified      = "unverified_content"
	CauseTruncatedTarget = "truncated_target"
	CauseOutOfScope      = "file_claim_out_of_scope"
	CauseOutsideWrite    = "outside_write"
	CauseHarnessFile     = "unexplained_harness_file"
	CauseHarnessNet      = "unexplained_harness_net"
	// CauseHarnessCommand is the twelfth cause. The protocol lists eleven;
	// decision O-30 (option b) makes an unexplained harness command, reported
	// apart, a reason for INCONCLUSIVE, so it is appended after the eleven
	// registered ones.
	CauseHarnessCommand = "unexplained_harness_command"
	// CauseTrace is the thirteenth cause: a trace that cannot be read whole,
	// with no evidence in the capture of who changed it (V-59). Appended
	// after the registered ones, as the twelfth was.
	CauseTrace = "trace_deleted_or_damaged"
)

// CauseOrder is the precedence list.
var CauseOrder = []string{
	CauseNoRoot, CauseTooLarge, CauseEventLoss, CauseIOUring, CauseVersion,
	CauseUnverified, CauseTruncatedTarget, CauseOutOfScope, CauseOutsideWrite,
	CauseHarnessFile, CauseHarnessNet, CauseHarnessCommand, CauseTrace,
}

// HarnessCommandMarker is the part of the verifier's reason for an
// unexplained declared harness command (O-30, V-43) that no other reason
// contains. It is matched case-insensitively. A reworded reason matches no
// cause and halts the analysis (Attribution.Unmatched), so a changed text
// is never counted silently under another cause.
const HarnessCommandMarker = "the adapter declares as the harness's own"

// OutOfCaptureMarker is the part of the verifier's reason for a git_commit
// claim set aside as out of capture (V-47). Such a claim is, like a file claim
// out of scope (V-23), a claim the capture could not observe, so it counts
// under that cause with the detail git_commit, at the same place in the
// precedence list. Matched case-insensitively.
const OutOfCaptureMarker = "git_commit claim(s) name a commit, which no probe observes"

// Hit is one cause found in one reason, with the counter or field it names
// where the protocol splits the cause.
type Hit struct {
	Cause  string `json:"cause"`
	Detail string `json:"detail,omitempty"`
}

// Event loss counters, named as the probe coverage record names them
// (models.ProbeCoverage), matched against pkg/verification's Assess texts.
var lossMarkers = []struct{ text, counter string }{
	{"ring buffer discarded", "RingbufDrops"},
	{"tracked_pids map was full", "UntrackedChildren"},
	{"state map was full", "StateMapFull"},
	{"events channel discarded", "ChannelDrops"},
	{"fanotify queue overflowed", "QueueOverflow"},
	{"still queued when the capture stopped", "UndrainedRecords"},
	{"no resolvable path and are not in the capture (v-39)", "UnresolvedInTree"},
	{"coverage was not recorded", "CoverageMissing"},
}

var unverifiedField = regexp.MustCompile(`([a-z_]+) x\d+`)

// ClassifyReason maps one reason to the causes it states. A reason that
// matches none gives no hit.
func ClassifyReason(reason string) []Hit {
	r := strings.ToLower(reason)
	var hits []Hit
	add := func(cause, detail string) { hits = append(hits, Hit{Cause: cause, Detail: detail}) }
	switch {
	case strings.Contains(r, "no root pid was recorded"),
		strings.Contains(r, "no observed event carries a pid"),
		strings.Contains(r, "carry no pid"):
		add(CauseNoRoot, "")
	}
	if strings.Contains(r, "too large to align") {
		add(CauseTooLarge, "")
	}
	if strings.Contains(r, "through io_uring") {
		add(CauseIOUring, "")
	}
	for _, m := range lossMarkers {
		if strings.Contains(r, m.text) {
			add(CauseEventLoss, m.counter)
		}
	}
	// The strict-version reason names decision I-57 in its own text.
	if strings.Contains(r, "i-57") {
		add(CauseVersion, "")
	}
	if strings.Contains(r, "state content the probe did not capture") {
		fields := map[string]bool{}
		for _, m := range unverifiedField.FindAllStringSubmatch(r, -1) {
			fields[m[1]] = true
		}
		if len(fields) == 0 {
			add(CauseUnverified, "")
		}
		for _, f := range sortedKeys(fields) {
			if f == "target" {
				add(CauseTruncatedTarget, "")
			} else {
				add(CauseUnverified, f)
			}
		}
	}
	if strings.Contains(r, "could not observe") {
		add(CauseOutOfScope, "")
	}
	if strings.Contains(r, OutOfCaptureMarker) {
		add(CauseOutOfScope, "git_commit")
	}
	if strings.Contains(r, "cannot place") {
		add(CauseOutsideWrite, "")
	}
	if strings.Contains(r, "under the harness's own directories") {
		add(CauseHarnessFile, "")
	}
	if strings.Contains(r, "to its declared service hosts") {
		add(CauseHarnessNet, "")
	}
	if strings.Contains(r, HarnessCommandMarker) {
		add(CauseHarnessCommand, "")
	}
	if strings.Contains(r, verification.TraceDeletedOrDamaged) {
		add(CauseTrace, "")
	}
	return hits
}

// Attribution is what the reasons of one INCONCLUSIVE run say.
type Attribution struct {
	// Causes lists each cause once, in precedence order.
	Causes []string `json:"causes"`
	// Details lists cause:detail pairs (loss counters, unverified fields).
	Details []string `json:"details,omitempty"`
	// Primary is the first cause in the precedence list that applies.
	Primary string `json:"primary"`
	// Unattributed is true when some reason matched no cause: an instrument
	// defect and a halt condition (protocol H3c). A reason the list does not
	// know, beside known ones, halts too, since its cause would otherwise go
	// uncounted.
	Unattributed bool `json:"unattributed"`
	// Unmatched lists the reasons no cause matched.
	Unmatched []string `json:"unmatched,omitempty"`
}

// Attribute classifies every reason of a verdict. Any reason that matches no
// cause is listed and makes the run unattributed; Primary is still the first
// cause the other reasons state, if any.
func Attribute(reasons []string) Attribution {
	have := map[string]bool{}
	details := map[string]bool{}
	var a Attribution
	for _, reason := range reasons {
		hits := ClassifyReason(reason)
		if len(hits) == 0 {
			a.Unmatched = append(a.Unmatched, reason)
		}
		for _, h := range hits {
			have[h.Cause] = true
			if h.Detail != "" {
				details[h.Cause+":"+h.Detail] = true
			}
		}
	}
	for _, c := range CauseOrder {
		if have[c] {
			a.Causes = append(a.Causes, c)
		}
	}
	a.Details = sortedKeys(details)
	if len(a.Causes) > 0 {
		a.Primary = a.Causes[0]
	}
	a.Unattributed = len(a.Causes) == 0 || len(a.Unmatched) > 0
	return a
}
