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
		{name: "state map full", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, StateMapFull: 2}}), wantReason: "net probe: a kernel state map was full, 2 record(s) lost"},
		{name: "channel drops", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, ChannelDrops: 1}}), wantReason: "net probe: events channel discarded 1"},
		{name: "io_uring socket operations are event loss (N-25)", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, IOURingNetOps: 2}}), wantReason: "net probe: tracked processes submitted 2 socket operation(s) through io_uring"},
		{name: "io_uring operations on a probe that did not run are ignored", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: false, IOURingNetOps: 2}}), wantComplete: true},
		{name: "fanotify overflow", cov: cov(map[string]models.ProbeCoverage{"fs": {Ran: true, QueueOverflow: true}}), wantReason: "fs probe: kernel fanotify queue overflowed"},
		{name: "records left in the fanotify queue at stop are event loss", cov: cov(map[string]models.ProbeCoverage{"fs": {Ran: true, UndrainedRecords: 5}}), wantReason: "fs probe: 5 record(s) were still queued when the capture stopped"},
		{name: "undrained records on a probe that did not run are ignored", cov: cov(map[string]models.ProbeCoverage{"fs": {Ran: false, UndrainedRecords: 5}}), wantComplete: true},
		{name: "unresolved file events are a note, not a loss (V-35)", cov: cov(map[string]models.ProbeCoverage{"fs": {Ran: true, UnresolvedPaths: 2}}), wantComplete: true, wantNotes: 1},
		{name: "unresolved file events of the agent's tree are event loss (V-39)", cov: cov(map[string]models.ProbeCoverage{"fs": {Ran: true, UnresolvedPaths: 5, UnresolvedInTree: 2}}), wantReason: "fs probe: 2 file event(s) by the agent's process tree had no resolvable path", wantNotes: 1},
		{name: "unresolved file events of the tree on a probe that did not run are ignored", cov: cov(map[string]models.ProbeCoverage{"fs": {Ran: false, UnresolvedPaths: 5, UnresolvedInTree: 2}}), wantComplete: true},
		{name: "unresolved file events on a probe that did not run are ignored", cov: cov(map[string]models.ProbeCoverage{"fs": {Ran: false, UnresolvedPaths: 2}}), wantComplete: true},
		{name: "counters on a probe that did not run are ignored", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: false, RingbufDrops: 9}}), wantComplete: true},
		{name: "faulted reads are a note, not a loss", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, FaultedReads: 4}}), wantComplete: true, wantNotes: 1},
		{name: "attach failure is a note, not a loss", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, Content: models.ContentAttachFailed}}), wantComplete: true, wantNotes: 1},
		{name: "response gaps are a note, not a loss (N-29)", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, Content: models.ContentActive, Responses: models.ContentActive, ResponseGaps: 3}}), wantComplete: true, wantNotes: 1},
		{name: "response gaps on a probe that did not run are ignored", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: false, ResponseGaps: 3}}), wantComplete: true},
		{name: "inactive response capture is a note", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, Content: models.ContentActive, Responses: models.ContentAttachFailed}}), wantComplete: true, wantNotes: 1},
		{name: "inactive response capture after a failed request capture is one note", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, Content: models.ContentAttachFailed, Responses: models.ContentAttachFailed}}), wantComplete: true, wantNotes: 1},
		{name: "responses identity only, or unrecorded in an older capture, is not a note", cov: cov(map[string]models.ProbeCoverage{"net": {Ran: true, Content: models.ContentIdentityOnly, Responses: models.ContentIdentityOnly}, "net2": {Ran: true, Content: models.ContentActive}}), wantComplete: true},
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

// A close published without a hash is a content gap: a note, not event loss.
func TestAssess_HashlessClosesAreANote(t *testing.T) {
	c := Assess(cov(map[string]models.ProbeCoverage{"fs": {Ran: true, HashlessCloses: 2}}))
	if !c.Complete || len(c.Notes) != 1 || !strings.Contains(c.Notes[0], "2 file close(s)") {
		t.Errorf("Assess = %+v, want complete with one note", c)
	}
}

// The response notes name their count and say no claim depends on them.
func TestAssess_ResponseNotes(t *testing.T) {
	c := Assess(cov(map[string]models.ProbeCoverage{"net": {Ran: true, Content: models.ContentActive, Responses: models.ContentAttachFailed, ResponseGaps: 2}}))
	if !c.Complete || len(c.Notes) != 2 {
		t.Fatalf("Assess = %+v, want complete with two notes", c)
	}
	if !strings.Contains(c.Notes[0], "response capture did not attach or never validated") {
		t.Errorf("first note = %q, want the inactive response capture", c.Notes[0])
	}
	if !strings.Contains(c.Notes[1], "2 response gap(s)") || !strings.Contains(c.Notes[1], "no claim depends on a response") {
		t.Errorf("second note = %q, want the gap count", c.Notes[1])
	}
}

// A capture written before V-39 has no unresolved_in_tree key: it reads as
// zero, so its host-wide count stays a note and its outcome is unchanged.
func TestAssess_ACaptureWithoutTheTreeCountIsUnchanged(t *testing.T) {
	f, err := models.ParseGroundTruthFile([]byte(`{"events": [], "coverage": {"schema": 1, "probes": {"fs": {"ran": true, "ringbuf_drops": 0, "untracked_children": 0, "state_map_full": 0, "channel_drops": 0, "unresolved_paths": 3}}}, "fs_scope": {"rule": "tree-or-workspace", "mounts": ["/"], "dropped_outside": 0, "unresolved": {"file_delete": 3}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if f.Coverage.Probes["fs"].UnresolvedInTree != 0 {
		t.Fatalf("UnresolvedInTree = %d, want 0 when the key is absent", f.Coverage.Probes["fs"].UnresolvedInTree)
	}
	if c := Assess(f.Coverage); !c.Complete || len(c.Notes) != 1 {
		t.Errorf("Assess = %+v, want complete with the V-35 note only", c)
	}
}

// A content method that read nothing while another did is a note of its
// own, and the probe's content stays active (N-42).
func TestAssess_SilentContentMethodIsANote(t *testing.T) {
	net := models.ProbeCoverage{Ran: true, Content: models.ContentActive, Responses: models.ContentActive, Diagnostics: &models.ProbeDiagnostics{ContentMethods: map[string]models.ContentMethodState{
		"tls-rustls-aead": {Requests: models.ContentActive, Responses: models.ContentActive},
		"tls-openssl-ex":  {Requests: models.ContentAttachFailed, Responses: models.ContentAttachFailed},
	}}}
	c := Assess(&models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"net": net}})
	want := "net probe: content method tls-openssl-ex did not validate (attach_failed), so claims that depend on it are not checked"
	if !c.Complete || len(c.Notes) != 1 || c.Notes[0] != want {
		t.Errorf("complete %v, notes %q; want complete with the note %q", c.Complete, c.Notes, want)
	}
}
