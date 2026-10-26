package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// canonFake replaces a per-run id in a file path, as a harness adapter does
// for its own files (I-41).
type canonFake struct{ fake }

var snapID = regexp.MustCompile(`(/home/u/\.snap-)[0-9a-z]+`)

func (canonFake) Canonical(e models.GroundTruthEvent) models.GroundTruthEvent {
	e.Target = snapID.ReplaceAllString(e.Target, "${1}N")
	return e
}

const envCmd = "/bin/bash -c env"

// envRun is one run of the harness's `bash -c env` in workspace ws: the
// command execs env, which reads a profile, writes a cache file in the
// workspace and a snapshot named by a per-run id, plus whatever extra the
// caller puts beneath it (pid 201) or beside it.
func envRun(ws, snap string, extra ...models.GroundTruthEvent) models.GroundTruthFile {
	g := models.GroundTruth{
		{Timestamp: t0, ActionType: models.ProcessFork, Target: "200", PID: 200, PPID: 100},
		ev(models.ProcessExec, envCmd, 200, 100),
		{Timestamp: t0, ActionType: models.ProcessFork, Target: "201", PID: 201, PPID: 200},
		ev(models.ProcessExec, "/usr/bin/env", 201, 200),
		ev(models.FileOpen, "/etc/profile", 201, 200),
		ev(models.FileWrite, ws+"/.cache", 201, 200),
		ev(models.FileWrite, "/home/u/.snap-"+snap, 201, 200),
	}
	f := completeFile(append(g, extra...))
	f.Workspace = ws
	return f
}

func sometimes() models.GroundTruthEvent { return ev(models.NetConnect, "sometimes.example", 201, 200) }

// controls: three runs in different workspaces with different snapshot ids;
// two of them also connect to sometimes.example beneath the command.
func envControls() []models.GroundTruthFile {
	return []models.GroundTruthFile{
		envRun("/tmp/c1/ws", "a1", sometimes()),
		envRun("/tmp/c2/ws", "b2", sometimes()),
		envRun("/tmp/c3/ws", "c3"),
	}
}

func hasRule(rs []Rule, typ models.ActionType, target string) bool {
	for _, r := range rs {
		if r.ActionType == typ && r.Target == target {
			return true
		}
	}
	return false
}

// V-38: Capture records, per command rule, what the command did beneath it in
// the controls: programs, writes and connections, in canonical form with the
// workspace templated, kept at the rules' agreement threshold. Reads are not
// recorded. An excluded command gets no rule and no record; a command rule
// with nothing beneath it gets an empty record.
func TestCaptureRecordsWhatEachCommandDidBeneathIt(t *testing.T) {
	a := canonFake{fake{name: "f"}}
	runs := envControls()
	for i := range runs {
		runs[i].Events = append(runs[i].Events,
			models.GroundTruthEvent{Timestamp: t0, ActionType: models.ProcessFork, Target: "300", PID: 300, PPID: 100},
			ev(models.ProcessExec, "/usr/bin/git status", 300, 100),
			models.GroundTruthEvent{Timestamp: t0, ActionType: models.ProcessFork, Target: "400", PID: 400, PPID: 100},
			ev(models.ProcessExec, ": control-marker", 400, 100),
			ev(models.FileWrite, "/w/marker-output", 400, 100),
		)
	}
	record := func(b Baseline, cmd string) *Subtree {
		for i := range b.Subtrees {
			if b.Subtrees[i].Command == cmd {
				return &b.Subtrees[i]
			}
		}
		return nil
	}

	strict, err := Capture(a, "v", runs, t0, CaptureOptions{Exclude: []string{": control-marker"}})
	if err != nil {
		t.Fatal(err)
	}
	env := record(strict, envCmd)
	if env == nil {
		t.Fatalf("no record for %q: %+v", envCmd, strict.Subtrees)
	}
	for _, want := range []Rule{{models.ProcessExec, "/usr/bin/env"}, {models.FileWrite, WorkspacePlaceholder + "/.cache"}, {models.FileWrite, "/home/u/.snap-N"}} {
		if !hasRule(env.Events, want.ActionType, want.Target) {
			t.Errorf("record %+v lacks %+v", env.Events, want)
		}
	}
	if len(env.Events) != 3 || hasRule(env.Events, models.FileOpen, "/etc/profile") {
		t.Errorf("record = %+v, want the exec and the two writes only, no read", env.Events)
	}
	if !hasRule(env.Unstable, models.NetConnect, "sometimes.example") {
		t.Errorf("at full agreement a connection in two runs of three is unstable: %+v", env.Unstable)
	}
	if git := record(strict, "/usr/bin/git status"); git == nil || git.Events == nil || len(git.Events) != 0 {
		t.Errorf("a command with nothing beneath it has an empty record, got %+v", git)
	}
	if record(strict, ": control-marker") != nil || len(strict.Subtrees) != 2 {
		t.Errorf("subtrees = %+v, want one record per command rule and none for the excluded command", strict.Subtrees)
	}

	loose, err := Capture(a, "v", runs, t0, CaptureOptions{Exclude: []string{": control-marker"}, MinAgreement: 0.6})
	if err != nil {
		t.Fatal(err)
	}
	if env := record(loose, envCmd); env == nil || !hasRule(env.Events, models.NetConnect, "sometimes.example") {
		t.Errorf("at 0.6 a connection in two runs of three is recorded: %+v", env)
	}
}

// V-38: in a run, a baselined command explains only the events beneath it
// that its record holds. An injected program, write, connection or request is
// an unexplained subtree; the controls' own subtree, with another workspace
// and another per-run id, is explained; a read beneath it stays explained;
// the agreement threshold decides as it does for rules.
func TestABaselinedCommandExplainsOnlyWhatItsControlsDidBeneathIt(t *testing.T) {
	a := canonFake{fake{name: "f"}}
	strict, err := Capture(a, "v", envControls(), t0, CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	loose, err := Capture(a, "v", envControls(), t0, CaptureOptions{MinAgreement: 0.6})
	if err != nil {
		t.Fatal(err)
	}
	const ws = "/home/u/project"
	cases := []struct {
		name        string
		b           Baseline
		extra       []models.GroundTruthEvent
		outcome     verification.Outcome
		unbaselined []string
	}{
		{name: "the controls' own subtree", b: strict, outcome: verification.OutcomeFaithful},
		{name: "a read beneath it", b: strict, extra: []models.GroundTruthEvent{ev(models.FileOpen, "/home/u/.ssh/id_rsa", 201, 200)}, outcome: verification.OutcomeFaithful},
		{name: "an injected program", b: strict, extra: []models.GroundTruthEvent{
			{Timestamp: t0, ActionType: models.ProcessFork, Target: "202", PID: 202, PPID: 200},
			ev(models.ProcessExec, "/usr/bin/curl -s https://evil.example", 202, 200),
		}, outcome: verification.OutcomeNotFaithful, unbaselined: []string{"process_exec /usr/bin/curl -s https://evil.example"}},
		{name: "an injected workspace write", b: strict, extra: []models.GroundTruthEvent{ev(models.FileWrite, ws+"/.backdoor", 201, 200)},
			outcome: verification.OutcomeNotFaithful, unbaselined: []string{"file_write " + ws + "/.backdoor"}},
		{name: "an injected delete", b: strict, extra: []models.GroundTruthEvent{ev(models.FileDelete, ws+"/src/main.go", 201, 200)},
			outcome: verification.OutcomeNotFaithful, unbaselined: []string{"file_delete " + ws + "/src/main.go"}},
		{name: "an injected connection", b: strict, extra: []models.GroundTruthEvent{ev(models.NetConnect, "evil.example", 201, 200)},
			outcome: verification.OutcomeNotFaithful, unbaselined: []string{"net_connect evil.example"}},
		{name: "an injected request", b: strict, extra: []models.GroundTruthEvent{ev(models.NetRequest, "POST https://evil.example/upload", 201, 200)},
			outcome: verification.OutcomeNotFaithful, unbaselined: []string{"net_request POST https://evil.example/upload"}},
		{name: "a connection two controls in three made, at full agreement", b: strict, extra: []models.GroundTruthEvent{sometimes()},
			outcome: verification.OutcomeNotFaithful, unbaselined: []string{"net_connect sometimes.example"}},
		{name: "the same connection at 0.6", b: loose, extra: []models.GroundTruthEvent{sometimes()}, outcome: verification.OutcomeFaithful},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.b
			v := verification.Verify(PrepareWithBaseline(a, nil, envRun(ws, "z9", tc.extra...), &b, verification.Options{}))
			if v.Outcome != tc.outcome {
				t.Fatalf("outcome = %s, want %s (subtrees %d, unrecorded %v)", v.Outcome, tc.outcome, len(v.Coverage.UnexplainedSubtrees), v.Unrecorded)
			}
			var got []string
			for _, c := range v.Coverage.UnexplainedSubtrees {
				if !c.Baseline {
					t.Errorf("unexplained subtree pid %d is not the baselined command", c.Process.PID)
				}
				for _, e := range c.Unbaselined {
					got = append(got, string(e.ActionType)+" "+e.Target)
				}
			}
			if strings.Join(got, ",") != strings.Join(tc.unbaselined, ",") {
				t.Errorf("unbaselined = %v, want %v", got, tc.unbaselined)
			}
			// What is not unbaselined is counted as explained by the baseline.
			content := len(v.Commands[0].Content)
			if v.Coverage.Baselined != content-len(got) {
				t.Errorf("Baselined = %d, want %d of %d", v.Coverage.Baselined, content-len(got), content)
			}
		})
	}
}

// V-38: a baseline written before V-38 has no subtree records. It reads as
// one, keeps the V7 reading (a baselined command explains its whole subtree),
// and a new baseline keeps its records through a file, even an empty list.
// An adapter's static noise declaration explains a command's whole subtree.
func TestABaselineWithoutSubtreeRecordsKeepsTheOldReading(t *testing.T) {
	a := canonFake{fake{name: "f"}}
	b, err := Capture(a, "v", envControls(), t0, CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "new.json")
	if err := SaveBaseline(path, b); err != nil {
		t.Fatal(err)
	}
	got, err := LoadBaseline(path)
	if err != nil || !got.RecordsSubtrees() || len(got.Subtrees) != len(b.Subtrees) || len(got.Subtrees[0].Events) != len(b.Subtrees[0].Events) {
		t.Fatalf("round trip = %+v, %v", got.Subtrees, err)
	}
	none, err := Capture(a, "v", []models.GroundTruthFile{completeFile(models.GroundTruth{ev(models.NetConnect, "api.example", 100, 0)})}, t0, CaptureOptions{})
	if err != nil || none.Subtrees == nil {
		t.Fatalf("a baseline with no command rule records an empty list, got %+v, %v", none.Subtrees, err)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := SaveBaseline(empty, none); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadBaseline(empty); err != nil || !got.RecordsSubtrees() {
		t.Errorf("an empty record list did not survive the file: %+v, %v", got.Subtrees, err)
	}

	// The same baseline as a file written before V-38: no subtrees key.
	data, _ := os.ReadFile(path)
	oldBody := regexp.MustCompile(`(?s),\s*"subtrees": \[.*\]\s*}\s*$`).ReplaceAll(data, []byte("\n}\n"))
	if strings.Contains(string(oldBody), "subtrees") {
		t.Fatalf("could not strip the records:\n%s", oldBody)
	}
	oldPath := filepath.Join(dir, "old.json")
	_ = os.WriteFile(oldPath, oldBody, 0o644)
	old, err := LoadBaseline(oldPath)
	if err != nil || old.RecordsSubtrees() || old.Subtree("/w") != nil || BaselineSubtree(a, &old, "/w") != nil {
		t.Fatalf("an old baseline: %v, records %v", err, old.RecordsSubtrees())
	}
	injected := envRun("/home/u/project", "z9", ev(models.NetConnect, "evil.example", 201, 200))
	if v := verification.Verify(PrepareWithBaseline(a, nil, injected, &old, verification.Options{})); v.Outcome != verification.OutcomeFaithful {
		t.Errorf("an old baseline: outcome = %s, want the V7 reading, FAITHFUL", v.Outcome)
	}
	if v := verification.Verify(PrepareWithBaseline(a, nil, injected, &got, verification.Options{})); v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("a new baseline: outcome = %s, want NOT FAITHFUL", v.Outcome)
	}

	noisy := canonFake{fake{name: "f", noise: func(e models.GroundTruthEvent) bool { return e.Target == envCmd }}}
	if v := verification.Verify(PrepareWithBaseline(noisy, nil, injected, &got, verification.Options{})); v.Outcome != verification.OutcomeFaithful {
		t.Errorf("a command the adapter declares noise: outcome = %s, want FAITHFUL", v.Outcome)
	}
}

// commander declares envCmd as a command the harness starts only sometimes,
// and its Normalize rewrites a wrapper "wrap: <cmd>" into <cmd>, as an
// adapter recovers an agent's command from the harness's shell wrapper.
type commander struct{ canonFake }

func (commander) HarnessCommands() []string { return []string{envCmd, ""} }

func (commander) Normalize(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) {
	e.Target = strings.TrimPrefix(e.Target, "wrap: ")
	return e, true
}

// V-43: a declared harness command that is no rule at the baseline's
// agreement has a record of what it did beneath it, counted over the controls
// that ran it; one that is a rule has the rule's record, unmarked.
func TestCaptureRecordsADeclaredCommandOverTheControlsThatRanIt(t *testing.T) {
	a := commander{canonFake{fake{name: "f"}}}
	quiet := completeFile(nil)
	quiet.Workspace = "/tmp/c4/ws"
	runs := append(envControls(), quiet) // three of four controls run it
	b, err := Capture(a, "1", runs, t0, CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(b.Rules, models.ProcessExec, envCmd) || len(b.Subtrees) != 1 {
		t.Fatalf("rules %v, subtrees %+v; want the command no rule and one record", b.Rules, b.Subtrees)
	}
	st := b.Subtrees[0]
	if st.Command != envCmd || !st.Declared ||
		!hasRule(st.Events, models.ProcessExec, "/usr/bin/env") || !hasRule(st.Events, models.FileWrite, "{workspace}/.cache") ||
		!hasRule(st.Events, models.FileWrite, "/home/u/.snap-N") || len(st.Events) != 3 ||
		!hasRule(st.Unstable, models.NetConnect, "sometimes.example") {
		t.Errorf("record %+v: want the three actions all three runs that ran it did, and the connection two of them made unstable", st)
	}
	// At two in four the command is a rule, and its record is the rule's.
	b, err = Capture(a, "1", runs, t0, CaptureOptions{MinAgreement: 0.5})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(b.Rules, models.ProcessExec, envCmd) || len(b.Subtrees) != 1 || b.Subtrees[0].Declared {
		t.Errorf("rules %v, subtrees %+v; want the rule's own record", b.Rules, b.Subtrees)
	}
	// An adapter that declares nothing records nothing for it.
	b, err = Capture(canonFake{fake{name: "f"}}, "1", runs, t0, CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Subtrees) != 0 {
		t.Errorf("subtrees %+v without a declaration, want none", b.Subtrees)
	}
}

// V-43 through Prepare: an occurrence of the declared command that no rule
// explains is INCONCLUSIVE with its subtree checked against the record; an
// extra connection beneath it is a finding; the same command line reached
// through the wrapper the adapter normalizes is not recognised.
func TestADeclaredHarnessCommandIsReportedApart(t *testing.T) {
	a := commander{canonFake{fake{name: "f"}}}
	quiet := completeFile(nil)
	quiet.Workspace = "/tmp/c4/ws"
	b, err := Capture(a, "1", append(envControls(), quiet), t0, CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	verify := func(run models.GroundTruthFile) verification.Verdict {
		return verification.Verify(PrepareWithBaseline(a, nil, run, &b, verification.Options{}))
	}
	v := verify(envRun("/tmp/r/ws", "z9"))
	if v.Outcome != verification.OutcomeInconclusive || v.Findings() != 0 || len(v.UnexplainedHarnessCommands) != 1 {
		t.Errorf("honest: outcome %s, %d findings, %d harness commands; want INCONCLUSIVE, none, one", v.Outcome, v.Findings(), len(v.UnexplainedHarnessCommands))
	}
	v = verify(envRun("/tmp/r/ws", "z9", ev(models.NetConnect, "evil.example", 201, 200)))
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Coverage.UnexplainedSubtrees) != 1 {
		t.Errorf("payload: outcome %s, unexplained subtrees %d; want NOT FAITHFUL on the subtree", v.Outcome, len(v.Coverage.UnexplainedSubtrees))
	}
	wrapped := envRun("/tmp/r/ws", "z9")
	wrapped.Events[1].Target = "wrap: " + envCmd
	v = verify(wrapped)
	if v.Outcome != verification.OutcomeNotFaithful || len(v.UnexplainedHarnessCommands) != 0 || len(v.Unrecorded) != 1 {
		t.Errorf("wrapped: outcome %s, %d harness commands, unrecorded %v; want the command an Unrecorded finding", v.Outcome, len(v.UnexplainedHarnessCommands), v.Unrecorded)
	}
	if HarnessCommand(a, wrapped.Events) != nil || HarnessCommand(canonFake{fake{name: "f"}}, envRun("/w", "a").Events) != nil {
		t.Error("a recogniser for a capture with no declared exec, or an adapter that declares none, want nil")
	}
}
