package gemini

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const (
	agentPID = 100
	cmdPID   = 200
	ws       = "/ws/basic"
	brain    = "/home/u/.gemini/antigravity-cli/brain/0b18d7d3-41b4-4dfe-b649-e8ba776c383a/.system_generated"
)

var t0 = time.Date(2026, 10, 13, 20, 2, 29, 0, time.UTC)

func ev(at time.Duration, pid uint32, a models.ActionType, target string) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: t0.Add(at), PID: pid, ActionType: a, Target: target}
}

func amb(e models.GroundTruthEvent) models.GroundTruthEvent { e.PathIsAmbiguous = true; return e }

func withIn(e models.GroundTruthEvent, h string) models.GroundTruthEvent { e.InputHash = &h; return e }

func withOut(e models.GroundTruthEvent, h string) models.GroundTruthEvent {
	e.OutputHash = &h
	return e
}

func render(g models.GroundTruth) string {
	var b strings.Builder
	for _, e := range g {
		a := ""
		if e.PathIsAmbiguous {
			a = " amb"
		}
		fmt.Fprintf(&b, "%d %s %s%s\n", e.PID, e.ActionType, e.Target, a)
	}
	return b.String()
}

// The three shapes of the paired basic capture (I-50), by the agent's own
// process, with the harness's transcript and step output writes between the
// calls as the capture has them.
func basicShapes() models.GroundTruth {
	a, b := ws+"/a.txt", ws+"/b.txt"
	ms := time.Millisecond
	return models.GroundTruth{
		// view_file b.txt: three opens.
		withIn(ev(0, agentPID, models.FileOpen, b), "sha256:b0"),
		withIn(ev(1*ms, agentPID, models.FileOpen, b), "sha256:b0"),
		withIn(ev(2*ms, agentPID, models.FileOpen, b), "sha256:b0"),
		ev(3*ms, agentPID, models.FileWrite, brain+"/logs/transcript.jsonl"),
		// write_to_file a.txt, new: the create, then the creating open.
		amb(ev(1000*ms, agentPID, models.FileWrite, ws)),
		withIn(ev(1000*ms+1, agentPID, models.FileOpen, a), emptyHash),
		ev(1000*ms+1, agentPID, models.FileWrite, a),
		withOut(ev(1000*ms+2, agentPID, models.FileClose, a), "sha256:a1"),
		amb(ev(1001*ms, agentPID, models.FileWrite, brain+"/steps/4")),
		withIn(ev(1001*ms+1, agentPID, models.FileOpen, brain+"/steps/4/output.txt"), emptyHash),
		ev(1002*ms, agentPID, models.FileWrite, brain+"/logs/transcript.jsonl"),
		// replace_file_content a.txt: the read, then the rewrite in place.
		withIn(ev(2000*ms, agentPID, models.FileOpen, a), "sha256:a1"),
		withIn(ev(2001*ms, agentPID, models.FileOpen, a), "sha256:a1"),
		ev(2001*ms+100, agentPID, models.FileWrite, a),
		withOut(ev(2001*ms+100, agentPID, models.FileClose, a), "sha256:a2"),
		ev(2002*ms, agentPID, models.FileWrite, brain+"/logs/transcript.jsonl"),
		// write_to_file b.txt over the existing file.
		withIn(ev(3000*ms, agentPID, models.FileOpen, b), "sha256:b0"),
		withIn(ev(3000*ms+100, agentPID, models.FileOpen, b), "sha256:b0"),
		ev(3000*ms+100, agentPID, models.FileWrite, b),
		withOut(ev(3000*ms+100, agentPID, models.FileClose, b), "sha256:b1"),
	}
}

func TestNormalizeStreamGivesTheClaimShapes(t *testing.T) {
	got := render(Adapter{}.NormalizeStream(basicShapes()))
	want := `100 file_open /ws/basic/b.txt
100 file_write ` + brain + `/logs/transcript.jsonl
100 file_open /ws/basic/a.txt
100 file_write /ws/basic/a.txt
100 file_close /ws/basic/a.txt
100 file_write ` + brain + `/steps/4 amb
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

// The first open of a run is the one kept: it carries the content the file
// had when the call began.
func TestCollapseKeepsTheFirstOpen(t *testing.T) {
	g := models.GroundTruth{
		withIn(ev(0, agentPID, models.FileOpen, ws+"/a.txt"), "sha256:first"),
		withIn(ev(1, agentPID, models.FileOpen, ws+"/a.txt"), "sha256:second"),
	}
	out := Adapter{}.NormalizeStream(g)
	if len(out) != 1 || *out[0].InputHash != "sha256:first" {
		t.Errorf("NormalizeStream = %+v, want the first open only", out)
	}
}

// What the folds leave alone: each case is one change to a shape they take.
func TestNormalizeStreamIsNarrow(t *testing.T) {
	a, b := ws+"/a.txt", ws+"/b.txt"
	fork := ev(0, cmdPID, models.ProcessFork, "200")
	for _, c := range []struct {
		name string
		g    models.GroundTruth
	}{
		{"opens of two files", models.GroundTruth{ev(0, agentPID, models.FileOpen, a), ev(1, agentPID, models.FileOpen, b)}},
		{"another event of the process between", models.GroundTruth{ev(0, agentPID, models.FileOpen, a), ev(1, agentPID, models.FileWrite, brain+"/logs/transcript.jsonl"), ev(2, agentPID, models.FileOpen, a)}},
		{"opens by two processes", models.GroundTruth{ev(0, agentPID, models.FileOpen, a), ev(1, agentPID+1, models.FileOpen, a)}},
		{"opens by a command", models.GroundTruth{fork, ev(1, cmdPID, models.FileOpen, a), ev(2, cmdPID, models.FileOpen, a)}},
		{"ambiguous opens", models.GroundTruth{amb(ev(0, agentPID, models.FileOpen, ws)), amb(ev(1, agentPID, models.FileOpen, ws))}},
		{"opens of the harness's file", models.GroundTruth{ev(0, agentPID, models.FileOpen, brain+"/logs/transcript.jsonl"), ev(1, agentPID, models.FileOpen, brain+"/logs/transcript.jsonl")}},
		{"a create before an open with content", models.GroundTruth{amb(ev(0, agentPID, models.FileWrite, ws)), withIn(ev(1, agentPID, models.FileOpen, a), "sha256:a1")}},
		{"a create before an open with no hash", models.GroundTruth{amb(ev(0, agentPID, models.FileWrite, ws)), ev(1, agentPID, models.FileOpen, a)}},
		{"a create in a later batch", models.GroundTruth{amb(ev(0, agentPID, models.FileWrite, ws)), withIn(ev(time.Microsecond, agentPID, models.FileOpen, a), emptyHash)}},
		{"a create of a file in another directory", models.GroundTruth{amb(ev(0, agentPID, models.FileWrite, ws)), withIn(ev(1, agentPID, models.FileOpen, ws+"/sub/a.txt"), emptyHash)}},
		{"a create with another event of the process between", models.GroundTruth{amb(ev(0, agentPID, models.FileWrite, ws)), ev(1, agentPID, models.FileClose, b), withIn(ev(2, agentPID, models.FileOpen, a), emptyHash)}},
		{"a create by a command", models.GroundTruth{fork, amb(ev(1, cmdPID, models.FileWrite, ws)), withIn(ev(2, cmdPID, models.FileOpen, a), emptyHash)}},
		{"a create of the harness's file", models.GroundTruth{amb(ev(0, agentPID, models.FileWrite, brain+"/steps/4")), withIn(ev(1, agentPID, models.FileOpen, brain+"/steps/4/output.txt"), emptyHash)}},
		{"a write of the directory that is not ambiguous", models.GroundTruth{ev(0, agentPID, models.FileWrite, ws), withIn(ev(1, agentPID, models.FileOpen, a), emptyHash)}},
		{"a create with nothing after it", models.GroundTruth{amb(ev(0, agentPID, models.FileWrite, ws))}},
	} {
		if got := (Adapter{}).NormalizeStream(c.g); render(got) != render(c.g) {
			t.Errorf("%s: NormalizeStream =\n%s\nwant it unchanged:\n%s", c.name, render(got), render(c.g))
		}
	}
}

// The calls of the basic capture, claimed as Parse claims them, against the
// shapes the capture showed: every claim pairs and nothing is left over. On the
// raw events the extra opens and the create are Unrecorded.
func TestTheMeasuredShapesVerifyEndToEnd(t *testing.T) {
	g := basicShapes()
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
	// The harness's own files are explained, as a baseline would.
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

// rawAdapter is the adapter without its stream normalization.
type rawAdapter struct{ inner Adapter }

func (r rawAdapter) Name() string                                { return r.inner.Name() }
func (r rawAdapter) Detect(p string) bool                        { return r.inner.Detect(p) }
func (r rawAdapter) Process() agent.ProcessModel                 { return r.inner.Process() }
func (r rawAdapter) IsHarnessNoise(models.GroundTruthEvent) bool { return false }
func (r rawAdapter) Parse(p string) (models.Trajectory, agent.Report, error) {
	return r.inner.Parse(p)
}
func (r rawAdapter) Normalize(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) {
	return r.inner.Normalize(e)
}
func (r rawAdapter) Expresses(e models.TrajectoryEntry, f string) bool {
	return r.inner.Expresses(e, f)
}
