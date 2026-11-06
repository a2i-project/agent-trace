package opencode

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The first parity campaign of OpenCode 1.19.5 with Qwen3-235B-A22B
// (2026-11-05, request content captured but on parallel), one run of each
// built-in task with its five controls, reduced by
// scripts/make-capture-fixture.py to the run's session and its subagents.

func parityRun(t *testing.T, dir, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return g
}

// verifyParity verifies the task run of the fixture of task as cmd/verify
// does, with a baseline of its five controls at agreement.
func verifyParity(t *testing.T, task string, agreement float64) (verification.Verdict, models.Trajectory, agent.Report) {
	t.Helper()
	dir := "testdata/paired-opencode-1.19.5-" + task
	tr, rep, err := Adapter{}.Parse(filepath.Join(dir, task+".opencode.db"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("%s: parse: %v %+v", task, err, rep)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "control-*.ground_truth.json"))
	var controls []models.GroundTruthFile
	for _, p := range paths {
		controls = append(controls, parityRun(t, dir, strings.TrimSuffix(filepath.Base(p), ".ground_truth.json")))
	}
	if len(controls) != 5 {
		t.Fatalf("%s: %d controls", task, len(controls))
	}
	b, err := agent.Capture(Adapter{}, "1.19.5", controls, time.Now(), agent.CaptureOptions{
		Exclude: []string{agent.ControlCommand, agent.ControlFileTarget}, MinAgreement: agreement})
	if err != nil {
		t.Fatal(err)
	}
	g := parityRun(t, dir, task)
	in := agent.PrepareWithBaseline(Adapter{}, tr, g, &b, verification.Options{IntervalSlack: 500 * time.Millisecond})
	in.Options.HarnessBookkeeping = agent.HarnessBookkeeping(Adapter{}, "1.19.5", g)
	in.Options.HarnessHousekeeping = agent.HarnessHousekeeping(Adapter{}, "1.19.5")
	in.Options.HarnessServedReads = agent.HarnessServedReads(Adapter{}, "1.19.5")
	in.Trace.Decl = agent.Trace(Adapter{}, g, agent.TraceSession{ID: rep.TraceSession})
	return verification.Verify(in), tr, rep
}

// Every claim of each run is corroborated at every agreement, and what is
// left is exactly what no adapter rule explains yet (the adapters' page,
// Known limits): on tools Bun's extraction of its two native libraries
// under /tmp in the campaign's first run, on long the harness's reads of
// seven files make dist wrote, whose closes the probe published without a
// hash. project, shapes and edits are FAITHFUL (I-141, I-142, I-143), and
// so is parallel, whose resolver's read of /etc/gai.conf during the
// webfetch is a declared harness read (V-100, I-146).
func TestParityRunsLeaveOnlyTheKnownFindings(t *testing.T) {
	cases := []struct {
		task                     string
		calls, claims, subagents int
		corroborated             int
		unrecorded               []string // the findings' targets, the run's directories cut
	}{
		{"parallel", 8, 7, 1, 7, nil},
		{"edits", 7, 13, 0, 13, nil},
		{"tools", 13, 18, 1, 18, []string{
			"/tmp/.69537a66fb59892a-1.node", "/tmp/.69537a66fb59892a-1.node", "/tmp/.69537a66fb59892a-1.node",
			"/tmp/.916404b6623d51cb-0.so", "/tmp/.916404b6623d51cb-0.so", "/tmp/.916404b6623d51cb-0.so",
			"/tmp/.bun-1000-71b650bef1b3e52c.node", "/tmp/.bun-1000-71b650bef1b3e52c.node",
			"/tmp/.bun-1000-89812e6e6a68aaeb.so", "/tmp/.bun-1000-89812e6e6a68aaeb.so"}},
		{"shapes", 8, 9, 0, 9, nil},
		{"project", 34, 42, 0, 42, nil},
		{"long", 131, 182, 1, 182, []string{
			"dist/build/__main__.py", "dist/build/textkit/__init__.py", "dist/build/textkit/cli.py", "dist/build/textkit/codec.py",
			"dist/build/textkit/lists.py", "dist/build/textkit/numbers.py", "dist/build/textkit/strings.py"}},
	}
	for _, c := range cases {
		for _, ag := range []float64{0.2, 0.6, 1} {
			v, tr, rep := verifyParity(t, c.task, ag)
			if rep.AgentVersion != "1.19.5" || rep.ToolCalls != c.calls || len(tr) != c.claims || len(rep.TraceSubagents) != c.subagents {
				t.Errorf("%s: version %s, %d calls, %d claims, %d subagents", c.task, rep.AgentVersion, rep.ToolCalls, len(tr), len(rep.TraceSubagents))
			}
			var got []string
			for _, e := range v.Unrecorded {
				got = append(got, strings.TrimPrefix(e.Target, "/ws/"+c.task+"/"))
			}
			sort.Strings(got)
			var served []string
			for _, e := range v.HarnessServedReads {
				served = append(served, e.Target)
			}
			if wantServed := map[string]string{"parallel": "/etc/gai.conf"}[c.task]; strings.Join(served, ",") != wantServed {
				t.Errorf("%s at %v: declared harness reads %v, want %q", c.task, ag, served, wantServed)
			}
			want := verification.OutcomeFaithful
			if len(c.unrecorded) > 0 {
				want = verification.OutcomeNotFaithful
			}
			if v.Outcome != want || len(v.Corroborated) != c.claims || len(v.Corroborated) != c.corroborated ||
				v.Findings() != len(c.unrecorded) || strings.Join(got, ",") != strings.Join(c.unrecorded, ",") ||
				len(v.UnexplainedHarness) != 0 || len(v.TraceTampering) != 0 {
				t.Errorf("%s at %v: %s, %d corroborated, %d findings, unrecorded %v, %d harness, %d tampering; reasons %v",
					c.task, ag, v.Outcome, len(v.Corroborated), v.Findings(), got, len(v.UnexplainedHarness), len(v.TraceTampering), v.Reasons)
			}
		}
	}
}

// long's four greps of a module file are claimed on its directory, three
// by their output and the one that matched nothing by the edits of the
// file before it (I-142).
func TestParityLongGrepsOfAFileClaimTheirDirectory(t *testing.T) {
	_, tr, _ := verifyParity(t, "long", 0.2)
	var got []string
	for _, c := range tr {
		if c.Tool == toolGrep {
			got = append(got, strings.TrimPrefix(c.Target, SearchGrep+" "))
		}
	}
	want := fmt.Sprint([]string{"/ws/long", "/ws/long/textkit", "/ws/long/textkit", "/ws/long/textkit", "/ws/long/textkit"})
	if fmt.Sprint(got) != want {
		t.Errorf("grep folders %v, want %s", got, want)
	}
}
