package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func cov(probes map[string]models.ProbeCoverage) *models.Coverage {
	return &models.Coverage{Schema: models.CoverageSchema, Probes: probes}
}

func TestAssess(t *testing.T) {
	tests := []struct {
		name         string
		cov          *models.Coverage
		wantComplete bool
		wantReason   string // substring of the first reason
		wantNotes    int
	}{
		{name: "nil coverage is unknown, not complete", cov: nil, wantReason: "not recorded"},
		{name: "clean run", cov: cov(map[string]models.ProbeCoverage{"proc": {Ran: true}, "fs": {Ran: true}}), wantComplete: true},
		{name: "no probes recorded is complete", cov: cov(nil), wantComplete: true},
		{name: "ring buffer drops", cov: cov(map[string]models.ProbeCoverage{"proc": {Ran: true, RingbufDrops: 2}}), wantReason: "proc probe: kernel ring buffer discarded 2"},
		{name: "untracked children", cov: cov(map[string]models.ProbeCoverage{"proc": {Ran: true, UntrackedChildren: 3}}), wantReason: "proc probe: tracked_pids map was full, 3 descendant(s)"},
		{name: "untracked children on a probe that did not run are ignored", cov: cov(map[string]models.ProbeCoverage{"proc": {Ran: false, UntrackedChildren: 3}}), wantComplete: true},
		{name: "channel drops", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, ChannelDrops: 1}}), wantReason: "net probe: events channel discarded 1"},
		{name: "fanotify overflow", cov: cov(map[string]models.ProbeCoverage{"fs": {Ran: true, QueueOverflow: true}}), wantReason: "fs probe: kernel fanotify queue overflowed"},
		{name: "counters on a probe that did not run are ignored", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: false, RingbufDrops: 9}}), wantComplete: true},
		{name: "faulted reads are a note, not a loss", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, FaultedReads: 4}}), wantComplete: true, wantNotes: 1},
		{name: "attach failure is a note, not a loss", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, Content: models.ContentAttachFailed}}), wantComplete: true, wantNotes: 1},
		{name: "identity only is not a note", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, Content: models.ContentIdentityOnly}}), wantComplete: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Assess(tc.cov)
			if got.Complete != tc.wantComplete {
				t.Fatalf("Complete = %v, want %v (reasons %v)", got.Complete, tc.wantComplete, got.Reasons)
			}
			if tc.wantComplete && len(got.Reasons) != 0 {
				t.Errorf("complete but has reasons: %v", got.Reasons)
			}
			if !tc.wantComplete && (len(got.Reasons) == 0 || !strings.Contains(got.Reasons[0], tc.wantReason)) {
				t.Errorf("reasons = %v, want first containing %q", got.Reasons, tc.wantReason)
			}
			if len(got.Notes) != tc.wantNotes {
				t.Errorf("notes = %v, want %d", got.Notes, tc.wantNotes)
			}
		})
	}
}

func TestAssess_ReasonsAreOrderedByProbeName(t *testing.T) {
	got := Assess(cov(map[string]models.ProbeCoverage{
		"proc": {Ran: true, RingbufDrops: 1},
		"fs":   {Ran: true, QueueOverflow: true},
		"net":  {Ran: true, ChannelDrops: 1},
	}))
	want := []string{"fs probe", "net probe", "proc probe"}
	if len(got.Reasons) != 3 {
		t.Fatalf("reasons = %v", got.Reasons)
	}
	for i, w := range want {
		if !strings.HasPrefix(got.Reasons[i], w) {
			t.Errorf("reason %d = %q, want prefix %q", i, got.Reasons[i], w)
		}
	}
}

func TestConclude(t *testing.T) {
	complete := Completeness{Complete: true}
	lossy := Completeness{Reasons: []string{"x"}}
	tests := []struct {
		name     string
		faithful bool
		c        Completeness
		want     Outcome
		wantExit int
	}{
		{"faithful and complete", true, complete, OutcomeFaithful, 0},
		{"faithful but incomplete is inconclusive", true, lossy, OutcomeInconclusive, 2},
		{"not faithful and complete", false, complete, OutcomeNotFaithful, 1},
		{"not faithful stays not faithful under loss", false, lossy, OutcomeNotFaithful, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Conclude(Verdict{Faithful: tc.faithful}, tc.c)
			if got != tc.want {
				t.Errorf("Conclude = %v, want %v", got, tc.want)
			}
			if got.ExitCode() != tc.wantExit {
				t.Errorf("ExitCode = %d, want %d", got.ExitCode(), tc.wantExit)
			}
		})
	}
}

// Requirement (08 section 3.9): any loss counter above zero makes FAITHFUL
// unavailable. A run whose only defect is a full tracked_pids map must come
// out INCONCLUSIVE with exit code 2, never FAITHFUL.
func TestConclude_UntrackedChildrenAloneIsInconclusive(t *testing.T) {
	c := Assess(cov(map[string]models.ProbeCoverage{
		"proc": {Ran: true},
		"net":  {Ran: true, UntrackedChildren: 1},
	}))
	got := Conclude(Verdict{Faithful: true}, c)
	if got != OutcomeInconclusive || got.ExitCode() != 2 {
		t.Errorf("Conclude = %v (exit %d), want INCONCLUSIVE (exit 2)", got, got.ExitCode())
	}
}
