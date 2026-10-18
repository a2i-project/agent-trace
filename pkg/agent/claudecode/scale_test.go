package claudecode

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// A long session is built from a real paired capture by repeating it: replica
// r of the task's claims and events is shifted later in time by r periods, its
// pids are moved out of the way of every other replica's, its parallel blocks
// and threads get their own ids, and, when rename is set, each file path a
// file claim names gets a per-replica name, in the claims and in every event,
// so the replicas touch different files. The harness's own events repeat with
// their targets unchanged, at the rate the capture shows, and the baseline
// from the capture's controls explains them as it does in the capture. Without
// rename every replica touches the same files, the worst case for ambiguity.

// scaleFixture is a paired capture the long sessions are built from.
type scaleFixture struct {
	name, dir, label, version string
	controls                  []string
}

var scaleFixtures = []scaleFixture{
	// Three Reads in one message, a subagent's Bash, Grep, Glob, WebFetch and a
	// pipeline: parallel blocks (V-32) and a subagent thread.
	{"parallel", parallelDir, "parallel", "2.1.286", []string{"control-1", "control-2", "control-3"}},
	// Edits and writes in parallel blocks of six and ten claims, and Bash
	// commands, in a seeded project.
	{"project", projectDir, "project", "2.1.286", []string{"control-1", "control-2", "control-3"}},
	// A harness-implied read (V-33) and two parallel blocks.
	{"shapes", "testdata/paired-2.1.296-shapes", "shapes", "2.1.296", fiveControls},
	// Every tool, two parallel blocks, a subagent thread and network claims.
	{"tools", "testdata/paired-2.1.296-tools", "tools", "2.1.296", fiveControls},
}

var fiveControls = []string{"control-1", "control-2", "control-3", "control-4", "control-5"}

func (f scaleFixture) load(t testing.TB) (models.Trajectory, models.GroundTruthFile, agent.Baseline) {
	t.Helper()
	read := func(label string) models.GroundTruthFile {
		data, err := os.ReadFile(filepath.Join(f.dir, label+".ground_truth.json"))
		if err != nil {
			t.Fatal(err)
		}
		g, err := models.ParseGroundTruthFile(data)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		return g
	}
	tr, rep, err := Adapter{}.Parse(filepath.Join(f.dir, f.label+".session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ParseErrors) != 0 {
		t.Fatalf("%s: %v", f.name, rep.ParseErrors)
	}
	var runs []models.GroundTruthFile
	for _, l := range f.controls {
		runs = append(runs, read(l))
	}
	b, err := agent.Capture(Adapter{}, f.version, runs, time.Unix(0, 0), agent.CaptureOptions{Exclude: []string{controlCommand}})
	if err != nil {
		t.Fatal(err)
	}
	return tr, read(f.label), b
}

// replicate builds a session of k replicas of the capture.
func replicate(tr models.Trajectory, g models.GroundTruthFile, k int, rename bool) (models.Trajectory, models.GroundTruthFile) {
	first, last := g.Events[0].Timestamp, g.Events[0].Timestamp
	see := func(ts time.Time) {
		if ts.Before(first) {
			first = ts
		}
		if ts.After(last) {
			last = ts
		}
	}
	var maxPID uint32
	for _, e := range g.Events {
		see(e.Timestamp)
		maxPID = max(maxPID, e.PID, e.PPID)
	}
	for _, c := range tr {
		see(c.Timestamp)
		if c.End != nil {
			see(*c.End)
		}
	}
	period := last.Sub(first) + time.Second
	stride := maxPID + 1
	// The paths a file claim names, the ones a replica renames.
	named := map[string]bool{}
	for _, c := range tr {
		if verification.LaneOf(c.ActionType) == verification.LaneFS {
			named[c.Target] = true
		}
	}
	// A path is renamed with the temporaries of an atomic write of it
	// (name.tmp.<pid>.<random>), which the adapter folds into the path.
	path := func(p string, r int) string {
		if !rename || r == 0 {
			return p
		}
		base := p
		if i := strings.Index(p, ".tmp."); i > 0 {
			base = p[:i]
		}
		if !named[base] {
			return p
		}
		return filepath.Join(filepath.Dir(p), fmt.Sprintf("r%d-%s", r, filepath.Base(p)))
	}
	pid := func(p uint32, r int) uint32 {
		if p == 0 || p == g.RootPID {
			return p
		}
		return p + uint32(r)*stride
	}
	id := func(s string, r int) string {
		if s == "" || r == 0 {
			return s
		}
		return fmt.Sprintf("%s#%d", s, r)
	}

	out := g
	out.Events = make(models.GroundTruth, 0, k*len(g.Events))
	var claims models.Trajectory
	for r := 0; r < k; r++ {
		shift := time.Duration(r) * period
		for _, e := range g.Events {
			e.Timestamp = e.Timestamp.Add(shift)
			e.PID, e.PPID = pid(e.PID, r), pid(e.PPID, r)
			if verification.LaneOf(e.ActionType) == verification.LaneFS {
				e.Target = path(e.Target, r)
			}
			out.Events = append(out.Events, e)
		}
		for _, c := range tr {
			c.Timestamp = c.Timestamp.Add(shift)
			if c.End != nil {
				end := c.End.Add(shift)
				c.End = &end
			}
			if verification.LaneOf(c.ActionType) == verification.LaneFS {
				c.Target = path(c.Target, r)
			}
			c.BlockID, c.ThreadID = id(c.BlockID, r), id(c.ThreadID, r)
			claims = append(claims, c)
		}
	}
	if g.Coverage != nil {
		cov := *g.Coverage
		out.Coverage = &cov
	}
	return claims, out
}

// scaleInput is the verification input for a session of about n claims built
// from f, as cmd/verify prepares it with a baseline.
func scaleInput(t testing.TB, f scaleFixture, n int, rename bool) (verification.Input, int, int) {
	t.Helper()
	tr, g, b := f.load(t)
	k := max(1, (n+len(tr)-1)/len(tr))
	claims, long := replicate(tr, g, k, rename)
	in := agent.Prepare(Adapter{}, claims, long, b.Predicate(long.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond})
	in.BaselineSubtree = agent.BaselineSubtree(Adapter{}, &b, long.Workspace)
	in.Sensitive = agent.SensitiveInput(Adapter{}, long, &b)
	return in, len(claims), len(long.Events)
}

// laneSizes is the number of claims and observed events per lane of a
// verdict's alignment, and the largest product of the two.
func laneSizes(v verification.Verdict) (string, int) {
	var parts []string
	most := 0
	for _, la := range v.Alignments {
		n, m := 0, 0
		for _, e := range la.Edits {
			if e.ClaimIndex >= 0 {
				n++
			}
			if e.EventIndex >= 0 {
				m++
			}
		}
		parts = append(parts, fmt.Sprintf("%s %dx%d", la.Lane, n, m))
		most = max(most, n*m)
	}
	return strings.Join(parts, ", "), most
}

// counts summarizes a verdict as the numbers a replica multiplies.
func counts(v verification.Verdict) string {
	return fmt.Sprintf("%s corroborated=%d mismatched=%d unwitnessed=%d unrecorded=%d outside=%d unverified=%d implied=%d impliedUnpaired=%d subtrees=%d ambiguous=%v",
		v.Outcome, len(v.Corroborated), len(v.Mismatched), len(v.Unwitnessed), len(v.Unrecorded), len(v.OutsideInterval),
		len(v.Unverified), len(v.HarnessImplied), len(v.HarnessImpliedUnpaired), len(v.Coverage.UnexplainedSubtrees), v.Ambiguous)
}

// A replicated session reads as k copies of the capture: every count is k
// times the capture's and the outcome is the capture's. This is the check
// that the generator keeps the structure the verifier reads.
func TestLongSessionIsKCopiesOfTheCapture(t *testing.T) {
	for _, f := range scaleFixtures {
		t.Run(f.name, func(t *testing.T) {
			one, _, _ := scaleInput(t, f, 1, true)
			v1 := verification.Verify(one)
			in, _, _ := scaleInput(t, f, 5*len(one.Claims), true)
			v := verification.Verify(in)
			if v.Outcome != v1.Outcome {
				t.Errorf("outcome %s, want the capture's %s", v.Outcome, v1.Outcome)
			}
			for _, c := range []struct {
				name     string
				got, one int
			}{
				{"corroborated", len(v.Corroborated), len(v1.Corroborated)},
				{"mismatched", len(v.Mismatched), len(v1.Mismatched)},
				{"unwitnessed", len(v.Unwitnessed), len(v1.Unwitnessed)},
				{"unrecorded", len(v.Unrecorded), len(v1.Unrecorded)},
				{"implied", len(v.HarnessImplied), len(v1.HarnessImplied)},
				{"subtrees", len(v.Coverage.UnexplainedSubtrees), len(v1.Coverage.UnexplainedSubtrees)},
			} {
				if c.got != 5*c.one {
					t.Errorf("%s = %d, want 5 x %d", c.name, c.got, c.one)
				}
			}
			t.Logf("one: %s\nfive: %s", counts(v1), counts(v))
		})
	}
}

// A session of a thousand claims, the upper end of the campaign's hundreds
// of tool calls, aligns every lane within the budget (V-42): none is refused
// with ErrTooLarge. The lane sizes are logged.
func TestLongSessionsAlignWithinTheBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("long sessions")
	}
	for _, f := range scaleFixtures {
		in, nc, ne := scaleInput(t, f, 1000, true)
		v := verification.Verify(in)
		if len(v.Alignments) == 0 {
			t.Errorf("%s: not aligned: %v", f.name, v.Reasons)
			continue
		}
		lanes, _ := laneSizes(v)
		t.Logf("%s: %d claims, %d events, claims x events per lane %s; %s", f.name, nc, ne, lanes, counts(v))
	}
}

// BenchmarkVerifyLongSession runs Verify on long sessions built from each
// scale fixture: alignment per lane with V-31's tie-break, V-32's blocks,
// V-33's implied claims, coverage and the baseline's subtraction, as
// cmd/verify runs them. The input is built outside the timer.
func BenchmarkVerifyLongSession(b *testing.B) {
	for _, f := range scaleFixtures {
		for _, n := range []int{100, 300, 1000, 3000} {
			b.Run(fmt.Sprintf("%s/claims=%d", f.name, n), func(b *testing.B) {
				in, _, events := scaleInput(b, f, n, true)
				b.ReportAllocs()
				for b.Loop() {
					v := verification.Verify(in)
					if v.Outcome == verification.OutcomeInconclusive && len(v.Alignments) == 0 {
						b.Fatalf("not aligned: %v", v.Reasons)
					}
				}
				b.ReportMetric(float64(events), "events")
			})
		}
	}
}

// BenchmarkCaptureLongControls runs agent.Capture on control runs as long as
// the long sessions: each control is replicated like a task.
func BenchmarkCaptureLongControls(b *testing.B) {
	for _, f := range scaleFixtures {
		for _, k := range []int{1, 10, 100} {
			b.Run(fmt.Sprintf("%s/replicas=%d", f.name, k), func(b *testing.B) {
				var runs []models.GroundTruthFile
				events := 0
				for _, l := range f.controls {
					data, err := os.ReadFile(filepath.Join(f.dir, l+".ground_truth.json"))
					if err != nil {
						b.Fatal(err)
					}
					g, err := models.ParseGroundTruthFile(data)
					if err != nil {
						b.Fatal(err)
					}
					_, long := replicate(nil, g, k, false)
					runs = append(runs, long)
					events += len(long.Events)
				}
				b.ReportAllocs()
				for b.Loop() {
					if _, err := agent.Capture(Adapter{}, f.version, runs, time.Unix(0, 0), agent.CaptureOptions{Exclude: []string{controlCommand}}); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(events), "events")
			})
		}
	}
}
