package gemini

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The tests in this file mirror those of stream_test.go in the shape the
// probe reports since it names directory entries (P-25, I-56): a create is a
// file_write naming the created file, not an ambiguous write of its
// directory. The checked-in captures hold only the older shape.

// namedShapes is basicShapes with every create named.
func namedShapes() models.GroundTruth {
	g := basicShapes()
	for i, e := range g {
		if e.PathIsAmbiguous && e.ActionType == models.FileWrite {
			g[i] = ev(e.Timestamp.Sub(t0), e.PID, models.FileWrite, g[i+1].Target)
		}
	}
	return g
}

func TestNormalizeStreamGivesTheClaimShapesWithNames(t *testing.T) {
	got := render(Adapter{}.NormalizeStream(namedShapes()))
	// As with the older shape, the harness's own create of its step output
	// is left as the controls measure it.
	want := `100 file_open /ws/basic/b.txt
100 file_write ` + brain + `/logs/transcript.jsonl
100 file_open /ws/basic/a.txt
100 file_write /ws/basic/a.txt
100 file_close /ws/basic/a.txt
100 file_write ` + brain + `/steps/4/output.txt
100 file_open ` + brain + `/steps/4/output.txt
100 file_write ` + brain + `/logs/transcript.jsonl
100 file_open /ws/basic/a.txt
100 file_write /ws/basic/a.txt
100 file_close /ws/basic/a.txt
100 file_write ` + brain + `/logs/transcript.jsonl
100 file_open /ws/basic/b.txt
100 file_write /ws/basic/b.txt
100 file_close /ws/basic/b.txt
`
	if got != want {
		t.Errorf("NormalizeStream =\n%s\nwant\n%s", got, want)
	}
}

// What the create fold leaves alone in the named shape: each case is one
// change to the shape it takes. The name must be the opened file's exactly.
func TestNamedCreateFoldIsNarrow(t *testing.T) {
	a, b := ws+"/a.txt", ws+"/b.txt"
	fork := ev(0, cmdPID, models.ProcessFork, "200")
	for _, c := range []struct {
		name string
		g    models.GroundTruth
	}{
		{"a create of another file", models.GroundTruth{ev(0, agentPID, models.FileWrite, b), withIn(ev(1, agentPID, models.FileOpen, a), emptyHash)}},
		{"a create before an open with content", models.GroundTruth{ev(0, agentPID, models.FileWrite, a), withIn(ev(1, agentPID, models.FileOpen, a), "sha256:a1")}},
		{"a create before an open with no hash", models.GroundTruth{ev(0, agentPID, models.FileWrite, a), ev(1, agentPID, models.FileOpen, a)}},
		{"a create with another event of the process between", models.GroundTruth{ev(0, agentPID, models.FileWrite, a), ev(1, agentPID, models.FileClose, b), withIn(ev(2, agentPID, models.FileOpen, a), emptyHash)}},
		{"a create by a command", models.GroundTruth{fork, ev(1, cmdPID, models.FileWrite, a), withIn(ev(2, cmdPID, models.FileOpen, a), emptyHash)}},
		{"a create of the harness's file", models.GroundTruth{ev(0, agentPID, models.FileWrite, brain+"/steps/4/output.txt"), withIn(ev(1, agentPID, models.FileOpen, brain+"/steps/4/output.txt"), emptyHash)}},
		{"a hashed write", models.GroundTruth{withOut(ev(0, agentPID, models.FileWrite, a), "sha256:a0"), withIn(ev(1, agentPID, models.FileOpen, a), emptyHash)}},
		{"an ambiguous open", models.GroundTruth{ev(0, agentPID, models.FileWrite, a), withIn(amb(ev(1, agentPID, models.FileOpen, a)), emptyHash)}},
	} {
		if got := (Adapter{}).NormalizeStream(c.g); render(got) != render(c.g) {
			t.Errorf("%s: NormalizeStream =\n%s\nwant it unchanged:\n%s", c.name, render(got), render(c.g))
		}
	}
}

// The calls of the basic capture against the named shapes: every claim pairs
// and nothing is left over; without the folds the extra opens and the create
// are Unrecorded, as with the older shape.
func TestTheNamedShapesVerifyEndToEnd(t *testing.T) {
	g := namedShapes()
	ms := time.Millisecond
	claim := func(tool string, at, end time.Duration, a models.ActionType, target string, out *string) models.TrajectoryEntry {
		e := t0.Add(end)
		return models.TrajectoryEntry{Tool: tool, Timestamp: t0.Add(at), End: &e, ActionType: a, Target: target, OutputHash: out}
	}
	file := func(tool string, at, end time.Duration, p, h string) []models.TrajectoryEntry {
		return []models.TrajectoryEntry{
			claim(tool, at, end, models.FileOpen, p, nil),
			claim(tool, at, end, models.FileWrite, p, nil),
			claim(tool, at, end, models.FileClose, p, models.StringPtr(h)),
		}
	}
	tr := models.Trajectory{claim(toolViewFile, -ms, 3*ms, models.FileOpen, ws+"/b.txt", nil)}
	tr = append(tr, file(toolWriteFile, 999*ms, 1003*ms, ws+"/a.txt", "sha256:a1")...)
	tr = append(tr, file(toolReplace, 1999*ms, 2003*ms, ws+"/a.txt", "sha256:a2")...)
	tr = append(tr, file(toolWriteFile, 2999*ms, 3003*ms, ws+"/b.txt", "sha256:b1")...)
	harness := func(e models.GroundTruthEvent) bool { return harnessOwned.MatchString(e.Target) }
	cov := &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}}
	run := func(a agent.Adapter) verification.Verdict {
		return verification.Verify(agent.Prepare(a, tr, models.GroundTruthFile{Events: g, RootPID: agentPID, Workspace: ws, Coverage: cov}, harness,
			verification.Options{IntervalSlack: 500 * time.Millisecond}))
	}
	v := run(Adapter{})
	if v.Findings() != 0 || len(v.Corroborated) != len(tr) || v.Outcome != verification.OutcomeFaithful {
		t.Errorf("outcome %s, %d of %d corroborated, unrecorded %v, unwitnessed %v, mismatched %v",
			v.Outcome, len(v.Corroborated), len(tr), v.Unrecorded, v.Unwitnessed, v.Mismatched)
	}
	if raw := run(rawAdapter{}); len(raw.Unrecorded) != 5 {
		t.Errorf("without the folds %d unrecorded, want the 4 extra opens and the create: %v", len(raw.Unrecorded), raw.Unrecorded)
	}
}
