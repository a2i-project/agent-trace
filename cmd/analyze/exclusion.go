package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/attack"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// RunFacts is what the exclusion rules of protocol section 10.1 read about
// one run, gathered by the caller so the rules themselves are a pure function.
type RunFacts struct {
	// Status is the manifest's status: ok, failed or interrupted.
	Status string
	// ParseError is set when the session file did not parse or the files the
	// run needs were missing (X4: a transcript that does not parse).
	ParseError string
	// ManifestVersion is the version the runner recorded and SessionVersion
	// the one the session states ("" when the format states none).
	ManifestVersion string
	SessionVersion  string
	// VersionAfter is the version the runner read after the run, "" when it
	// did not record one.
	VersionAfter string
	// Recorded is the runner's own rule for a run that did not complete.
	Recorded *RecordedExclude
	// LossReasons are the completeness reasons of the task run's capture, one
	// per loss counter set; a capture with no coverage record gives one.
	LossReasons []string
	// Annotation is the operator's record (annotations.json).
	Annotation Annotation
	// Claims is the number of claims the adapter read.
	Claims int
}

// Exclusion is one rule that applies to a run.
type Exclusion struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// Exclusions returns every exclusion rule that applies to a run, in rule
// order. A run with any of X1, X3, X4 or X6 is out of H3a, H3b and H2; X1
// stays in H3c and H3d (they count completed runs); X3, X4 and X6 stay out of
// everything. X5 never excludes a run from H3: it sets a run aside from H2
// only when it has fewer than MinClaimsForSweep claims (see H2Excluded).
func Exclusions(f RunFacts) []Exclusion {
	var out []Exclusion
	if len(f.LossReasons) > 0 {
		out = append(out, Exclusion{X1, "loss: " + strings.Join(f.LossReasons, "; ")})
	}
	if f.ManifestVersion != "" && f.SessionVersion != "" && f.ManifestVersion != f.SessionVersion {
		out = append(out, Exclusion{X3, fmt.Sprintf("the manifest records version %s, the session states %s", f.ManifestVersion, f.SessionVersion)})
	}
	if f.ManifestVersion != "" && f.VersionAfter != "" && f.ManifestVersion != f.VersionAfter {
		out = append(out, Exclusion{X3, fmt.Sprintf("the runner read version %s before the run and %s after it", f.ManifestVersion, f.VersionAfter)})
	}
	if f.Status != "ok" {
		// The runner's own classification wins where it gives one of the
		// rules a non-completed run can have; anything else is X4.
		rule, reason := X4, "the runner's status for the run is "+quoteOr(f.Status, "absent")
		if r := f.Recorded; r != nil && (r.Rule == X3 || r.Rule == X4 || r.Rule == X6) {
			rule, reason = r.Rule, fmt.Sprintf("the runner recorded %s: %s", r.Rule, quoteOr(r.Reason, "no reason"))
		}
		if rule != X3 || !hasRule(out, X3) {
			out = append(out, Exclusion{rule, reason})
		}
	}
	if f.ParseError != "" {
		out = append(out, Exclusion{X4, f.ParseError})
	}
	if f.Annotation.X4 != "" {
		out = append(out, Exclusion{X4, "annotated: " + f.Annotation.X4})
	}
	if f.Annotation.X6 != "" {
		out = append(out, Exclusion{X6, "annotated: " + f.Annotation.X6})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

func quoteOr(s, empty string) string {
	if s == "" {
		return empty
	}
	return s
}

// Has reports whether rule appears among the exclusions.
func hasRule(ex []Exclusion, rule string) bool {
	for _, e := range ex {
		if e.Rule == rule {
			return true
		}
	}
	return false
}

// Scope of a run in the analyses, derived from its exclusions.
type Scope struct {
	// Kept: in H3a, H3b and H2 (no X1, X3, X4 or X6).
	Kept bool
	// Completed: in H3c and H3d (no X3, X4 or X6; X1 stays in).
	Completed bool
}

// ScopeOf applies the effect column of protocol 10.1.
func ScopeOf(ex []Exclusion) Scope {
	hard := hasRule(ex, X3) || hasRule(ex, X4) || hasRule(ex, X6)
	return Scope{Kept: !hard && !hasRule(ex, X1), Completed: !hard}
}

// H2Excluded says whether X5 sets a run aside from the sweep: the generators
// need at least MinClaimsForSweep claims of the agent's own, since they
// refuse harness-implied claims (protocol 5.1).
func H2Excluded(claims models.Trajectory) (Exclusion, bool) {
	own, implied := attack.WithoutImplied(claims)
	if len(own) < MinClaimsForSweep {
		return Exclusion{X5, fmt.Sprintf("%d claim(s) of the agent's own (%d harness-implied left out), the generators need %d", len(own), implied, MinClaimsForSweep)}, true
	}
	return Exclusion{}, false
}

// SlotReport is the X4 feasibility count of one agent: slots, failed slots
// and attempts moved aside.
type SlotReport struct {
	Agent        string   `json:"agent"`
	Slots        int      `json:"slots"`
	FailedSlots  int      `json:"failed_slots"`
	MovedAside   int      `json:"attempts_moved_aside"`
	FailedShare  *float64 `json:"failed_share"`
	OverLimit    bool     `json:"over_limit"`
	FailedSlotID []string `json:"failed_slot_runs,omitempty"`
}

// Slots counts, per agent, the slots of the campaign and those whose run did
// not complete, against MaxFailedSlotShare (X4).
func Slots(c *Campaign) []SlotReport {
	by := map[string]*SlotReport{}
	for _, r := range c.Manifest.Runs {
		s := by[r.Agent]
		if s == nil {
			s = &SlotReport{Agent: r.Agent}
			by[r.Agent] = s
		}
		s.Slots++
		s.MovedAside += c.FailedAttempts[c.ID(r)]
		// X4's line counts harness errors; a run the runner classified X3
		// or X6 is excluded but is not a failed slot.
		if r.Status != "ok" && (r.Exclusion == nil || (r.Exclusion.Rule != X3 && r.Exclusion.Rule != X6)) {
			s.FailedSlots++
			s.FailedSlotID = append(s.FailedSlotID, c.ID(r))
		}
	}
	var out []SlotReport
	for _, a := range sortedKeys(by) {
		s := by[a]
		s.FailedShare = ratioPtr(s.FailedSlots, s.Slots)
		s.OverLimit = s.FailedShare != nil && *s.FailedShare > MaxFailedSlotShare
		sort.Strings(s.FailedSlotID)
		out = append(out, *s)
	}
	return out
}
