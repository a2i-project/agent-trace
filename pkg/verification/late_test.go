package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// V-56: an open of a declared background output file more than a second
// after every write-class event on it is the agent's. The baseline does not explain it
// and it is not harness-owned, so an unclaimed one is Unrecorded and a
// claimed one is a plain corroboration; the harness's opens up to the last
// write stay explained.
func TestVerify_AnOpenOfABackgroundOutputAfterItsLastWriteIsTheAgents(t *testing.T) {
	const out = "/tmp/h/tasks/b1.output"
	background := func(p string) bool { return strings.HasSuffix(p, ".output") }
	owned := func(p string) bool { return strings.HasPrefix(p, "/tmp/h/") }
	base := func(e models.GroundTruthEvent) bool { return e.Target == out }
	// The harness creates the file, opens it while the command runs, and
	// writes and closes it when the command ends, at 30.
	harness := []models.GroundTruthEvent{agentEv(1, models.FileWrite, out), agentEv(2, models.FileOpen, out), agentEv(20, models.FileOpen, out), agentEv(30, models.FileOpen, out), agentEv(30, models.FileWrite, out), agentEv(30, models.FileClose, out)}
	with := func(evs ...models.GroundTruthEvent) models.GroundTruth {
		return append(append(models.GroundTruth{}, harness...), evs...)
	}
	verify := func(decl func(string) bool, claims models.Trajectory, g models.GroundTruth) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: base, Options: Options{HarnessOwned: owned, BackgroundOutput: decl}})
	}
	read := agentEv(3000, models.FileOpen, out)

	claimed := verify(background, models.Trajectory{claimAt(3000, models.FileOpen, out)}, with(read))
	if claimed.Outcome != OutcomeFaithful || len(claimed.Corroborated) != 1 || len(claimed.CorroboratedHarnessShared) != 0 {
		t.Errorf("a claimed late read: %s, %d corroborated, %d shared with the harness", claimed.Outcome, len(claimed.Corroborated), len(claimed.CorroboratedHarnessShared))
	}

	omitted := verify(background, nil, with(read))
	if omitted.Outcome != OutcomeNotFaithful || len(omitted.Unrecorded) != 1 || omitted.Unrecorded[0].Timestamp != read.Timestamp || len(omitted.UnexplainedHarness) != 0 {
		t.Errorf("an unclaimed late read: %s, unrecorded %v, unexplained harness %v", omitted.Outcome, omitted.Unrecorded, omitted.UnexplainedHarness)
	}

	if v := verify(background, nil, with()); v.Outcome != OutcomeFaithful || v.Findings() != 0 {
		t.Errorf("the harness's own opens up to the last write: %s, %d findings", v.Outcome, v.Findings())
	}
	// The harness reads a command's output right after its last write: an
	// open within lateOpenGrace of it is still the harness's.
	if v := verify(background, nil, with(agentEv(30, models.FileOpen, out), agentEv(1030, models.FileOpen, out))); v.Findings() != 0 {
		t.Errorf("opens up to a second after the last write: %d findings", v.Findings())
	}
	if v := verify(nil, nil, with(read)); v.Outcome != OutcomeFaithful || v.Findings() != 0 {
		t.Errorf("without the declaration the late read is explained, as before: %s, %d findings", v.Outcome, v.Findings())
	}
	// A declared file the capture holds no write of has no late open.
	other := "/tmp/h/tasks/b2.output"
	base2 := func(e models.GroundTruthEvent) bool { return e.Target == other }
	v := Verify(Input{Ground: models.GroundTruth{agentEv(5, models.FileOpen, other), agentEv(6000, models.FileOpen, other)}, RootPID: agentPID, Coverage: completeCov(), Baseline: base2, Options: Options{HarnessOwned: owned, BackgroundOutput: background}})
	if v.Findings() != 0 {
		t.Errorf("a declared file never written: %d findings", v.Findings())
	}
}

// BaselineInEffect is the predicate Verify applies: the late open is not
// recognised, every other event is as Input.Baseline says.
func TestBaselineInEffectLeavesOutLateOpens(t *testing.T) {
	const out = "/tmp/h/tasks/b1.output"
	in := Input{
		Ground:   models.GroundTruth{agentEv(1, models.FileOpen, out), agentEv(2, models.FileClose, out), agentEv(1500, models.FileOpen, out)},
		Baseline: func(e models.GroundTruthEvent) bool { return e.Target == out },
		Options:  Options{BackgroundOutput: func(p string) bool { return p == out }},
	}
	b := in.BaselineInEffect()
	if !b(in.Ground[0]) || !b(in.Ground[1]) || b(in.Ground[2]) {
		t.Errorf("recognised: %v %v %v, want true true false", b(in.Ground[0]), b(in.Ground[1]), b(in.Ground[2]))
	}
	in.Options.BackgroundOutput = nil
	if b := in.BaselineInEffect(); !b(in.Ground[2]) {
		t.Error("without the declaration the baseline is Input.Baseline")
	}
}
