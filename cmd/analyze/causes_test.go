package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/config"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

func TestPrecedenceListIsTheProtocolsEleven(t *testing.T) {
	want := []string{CauseNoRoot, CauseTooLarge, CauseEventLoss, CauseIOUring, CauseVersion, CauseUnverified, CauseTruncatedTarget, CauseOutOfScope, CauseOutsideWrite, CauseHarnessFile, CauseHarnessNet}
	if !reflect.DeepEqual(CauseOrder[:11], want) {
		t.Errorf("the first eleven causes must be the protocol's list in order, got %v", CauseOrder[:11])
	}
	if CauseOrder[11] != CauseHarnessCommand || len(CauseOrder) != 12 {
		t.Errorf("the O-30 cause comes after the eleven: %v", CauseOrder)
	}
}

// The strings below are the texts pkg/verification produces. The loss, no-pid
// and root-pid ones come from the verifier itself, so a change of wording
// breaks this test; the others are copied from the unexported reason
// functions, with the function named.
func TestClassifyReasonOnTheVerifiersOwnTexts(t *testing.T) {
	v := verification.Verify(verification.Input{})
	if len(v.Reasons) == 0 {
		t.Fatal("verification without a root pid gave no reason")
	}
	if got := Attribute(v.Reasons); got.Primary != CauseNoRoot {
		t.Errorf("no root pid: %+v for %v", got, v.Reasons)
	}
	v = verification.Verify(verification.Input{RootPID: 7, Ground: models.GroundTruth{{ActionType: models.FileOpen, Target: "/x"}}})
	if got := Attribute(v.Reasons); got.Primary != CauseNoRoot {
		t.Errorf("events without a pid: %+v for %v", got, v.Reasons)
	}

	cov := &models.Coverage{Probes: map[string]models.ProbeCoverage{
		"proc": {Ran: true, RingbufDrops: 2, UntrackedChildren: 1, StateMapFull: 1, ChannelDrops: 1, UnresolvedInTree: 1},
		"fs":   {Ran: true, QueueOverflow: true, UndrainedRecords: 3},
		"net":  {Ran: true, IOURingNetOps: 4},
	}}
	a := Attribute(verification.Assess(cov).Reasons)
	wantDetails := []string{"event_loss:ChannelDrops", "event_loss:QueueOverflow", "event_loss:RingbufDrops", "event_loss:StateMapFull", "event_loss:UndrainedRecords", "event_loss:UnresolvedInTree", "event_loss:UntrackedChildren"}
	if !reflect.DeepEqual(a.Details, wantDetails) {
		t.Errorf("loss counters\n got %v\nwant %v", a.Details, wantDetails)
	}
	if !reflect.DeepEqual(a.Causes, []string{CauseEventLoss, CauseIOUring}) || a.Primary != CauseEventLoss || a.Unattributed || len(a.Unmatched) != 0 {
		t.Errorf("loss plus io_uring: %+v", a)
	}
	if a := Attribute(verification.Assess(nil).Reasons); a.Primary != CauseEventLoss || a.Details[0] != "event_loss:CoverageMissing" {
		t.Errorf("a missing coverage record is loss: %+v", a)
	}

	cases := []struct {
		name, reason, cause, detail string
	}{
		// verification.go, alignment errors.
		{"too large", "the trajectory or the observed sequence is too large to align: lane too large to align", CauseTooLarge, ""},
		// verification.go, unverifiedReason.
		{"unverified field", "2 claim(s) state content the probe did not capture (output_hash x2), so they are neither confirmed nor refuted", CauseUnverified, "output_hash"},
		{"truncated target", "1 claim(s) state content the probe did not capture (target x1), so they are neither confirmed nor refuted", CauseTruncatedTarget, ""},
		// verification.go, outOfScopeReason, outsideWritesReason, unexplainedHarnessReason, unexplainedHarnessNetReason.
		{"out of scope", "1 file claim(s) name a path the capture could not observe (outside its fs_scope), so they are neither confirmed nor refuted", CauseOutOfScope, ""},
		{"outside write", "1 write(s) in the workspace by a process the tree cannot place: the workspace changed under something the capture could not attribute", CauseOutsideWrite, ""},
		{"harness file", "3 file event(s) under the harness's own directories are explained by no claim and no baseline rule: harness activity the control runs did not show, or an action the agent hid there", CauseHarnessFile, ""},
		{"harness net", "1 connection(s) by the harness's own process to its declared service hosts are explained by no claim and no baseline rule", CauseHarnessNet, ""},
		// cmd/verify/version.go, versionCheck.reason.
		{"version", "the session was recorded by claude-code version 9.9.9, which config/agents.json does not configure (configured: 2.1.306): the adapter was verified on those versions only (--strict-version, I-57)", CauseVersion, ""},
		// The verifier's unexplainedHarnessCommandsReason (V-43, O-30), as the
		// verifier lane words it.
		{"harness command", "1 command(s) the adapter declares as the harness's own ran beneath the agent's process and are explained by no claim and no baseline rule: harness activity the control runs did not all show, or the same command line run by the agent and not reported; what each did beneath it is what the controls' same command did", CauseHarnessCommand, ""},
	}
	for _, c := range cases {
		a := Attribute([]string{c.reason})
		if a.Primary != c.cause || a.Unattributed {
			t.Errorf("%s: %+v", c.name, a)
		}
		if c.detail != "" && !contains(a.Details, c.cause+":"+c.detail) {
			t.Errorf("%s: details %v lack %s", c.name, a.Details, c.detail)
		}
	}
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func TestAttributeCountsEveryCauseAndPicksThePrimaryByPrecedence(t *testing.T) {
	reasons := []string{
		"1 connection(s) by the harness's own process to its declared service hosts are explained by no claim",
		"3 file event(s) under the harness's own directories are explained by no claim and no baseline rule",
		"2 claim(s) state content the probe did not capture (exit_code x1, target x1), so they are neither confirmed nor refuted",
	}
	a := Attribute(reasons)
	want := []string{CauseUnverified, CauseTruncatedTarget, CauseHarnessFile, CauseHarnessNet}
	if !reflect.DeepEqual(a.Causes, want) {
		t.Errorf("multi-cause list %v, want %v (precedence order)", a.Causes, want)
	}
	if a.Primary != CauseUnverified {
		t.Errorf("primary %s: unverified content (6) precedes the harness causes (10, 11)", a.Primary)
	}
	if !reflect.DeepEqual(a.Details, []string{"unverified_content:exit_code"}) {
		t.Errorf("details %v", a.Details)
	}
}

func TestAnUnmatchedReasonIsUnattributedAndListed(t *testing.T) {
	a := Attribute([]string{"alignment failed: boom"})
	if !a.Unattributed || a.Primary != "" || len(a.Unmatched) != 1 {
		t.Errorf("an INCONCLUSIVE with no listed cause is an instrument defect: %+v", a)
	}
	if b := Attribute(nil); !b.Unattributed {
		t.Errorf("no reasons at all cannot be attributed: %+v", b)
	}
	// A reason the list does not know beside a known one still halts (H3c):
	// otherwise a new INCONCLUSIVE cause would be counted under whatever
	// cause happened to accompany it.
	mixed := Attribute([]string{"1 file claim(s) name a path the capture could not observe", "something new"})
	if !mixed.Unattributed || len(mixed.Unmatched) != 1 || mixed.Primary != CauseOutOfScope {
		t.Errorf("a partly matched run keeps its known primary cause and is unattributed: %+v", mixed)
	}
	// The pre-V-43 guess at the O-30 text matches nothing, so it halts.
	if g := Attribute([]string{"1 command(s) run by the harness are an unexplained harness command"}); !g.Unattributed {
		t.Errorf("a harness-command text the verifier does not produce must not match: %+v", g)
	}
}

func TestVersionReasonMirrorsVerifyStrictVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agents.json")
	doc := map[string]any{"schema": 1, "adapters": map[string]any{"claude-code": map[string]any{"binary": "claude", "versions": []any{
		map[string]any{"version": "2.1.306", "verified": "2026-10-24", "fixtures": []string{"x"}}}}}}
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if r := versionReason(cfg, "claude-code", "2.1.306"); r != "" {
		t.Errorf("a configured version gives no reason: %q", r)
	}
	for _, c := range []struct{ adapter, version, want string }{
		{"claude-code", "2.1.1", "does not configure"},
		{"claude-code", "", "does not state"},
		{"gemini", "1.3.4", "has no entry"},
	} {
		r := versionReason(cfg, c.adapter, c.version)
		if !strings.Contains(r, c.want) || Attribute([]string{r}).Primary != CauseVersion {
			t.Errorf("%s %q: reason %q must say %q and attribute to cause 5", c.adapter, c.version, r, c.want)
		}
	}
	v := applyStrict(verification.Verdict{Outcome: verification.OutcomeNotFaithful, Unrecorded: make([]models.GroundTruthEvent, 2)}, "bad version (--strict-version, I-57)")
	if v.Outcome != verification.OutcomeInconclusive || v.Findings() != 2 || !strings.Contains(v.Reasons[0], "2 finding(s)") {
		t.Errorf("strict makes the outcome INCONCLUSIVE and keeps the findings: %+v", v)
	}
}
