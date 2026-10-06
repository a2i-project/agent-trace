package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// coverageOf runs the three stages the way Verify will: partition, subtract the
// baseline, align, check coverage.
func coverageOf(t *testing.T, claims models.Trajectory, g models.GroundTruth, b Baseline) (Coverage, Partition) {
	t.Helper()
	f := BuildForest(g, agentPID)
	p, _ := f.Partition(g).SubtractBaseline(b)
	as, err := Align(claims, p.Observed, Options{})
	if err != nil {
		t.Fatalf("Align: %v", err)
	}
	return CheckCoverage(p, as), p
}

func twoCommandTruth() models.GroundTruth {
	return models.GroundTruth{
		fork(1, 200, agentPID), execEv(2, 200, agentPID, "/bin/sh -c build"),
		fork(3, 201, 200), execEv(4, 201, 200, "/usr/bin/make"),
		fsEv(5, 201, "/w/out.o"), fsEv(6, 201, "/w/out.bin"),
		exitEv(7, 201, 200, "/usr/bin/make"),
		exitEv(8, 200, agentPID, "/bin/sh -c build"),
		fork(9, 300, agentPID), execEv(10, 300, agentPID, "/usr/bin/curl http://x"),
		fsEv(11, 300, "/w/downloaded"),
		exitEv(12, 300, agentPID, "/usr/bin/curl http://x"),
	}
}

func claimsFor(targets ...string) models.Trajectory {
	var tr models.Trajectory
	for _, x := range targets {
		tr = append(tr, claim(models.ProcessExec, x), claim(models.ProcessExit, x))
	}
	return tr
}

// The hundreds of events a build produces are explained by the one command the
// agent claimed, and are never compared against anything.
func TestCoverage_SubtreeEventsAreExplainedByTheirCommand(t *testing.T) {
	cov, _ := coverageOf(t, claimsFor("/bin/sh -c build", "/usr/bin/curl http://x"), twoCommandTruth(), nil)
	if !cov.Complete {
		t.Fatalf("coverage incomplete: %+v", cov)
	}
	// Content of the build: make's exec and exit, and its two file events. Of
	// the download: its one file event.
	if cov.Explained != 4+1 {
		t.Errorf("Explained = %d, want 5 subtree events", cov.Explained)
	}
}

// Omission cannot be evaded by hiding inside a command: you cannot run a command
// without creating a subtree, and a subtree nothing claims is left over (V3).
func TestCoverage_AnUnclaimedCommandIsAnOmission(t *testing.T) {
	cov, _ := coverageOf(t, claimsFor("/bin/sh -c build"), twoCommandTruth(), nil)
	if cov.Complete {
		t.Fatal("coverage complete although a command was never claimed")
	}
	if len(cov.UnexplainedSubtrees) != 1 || cov.UnexplainedSubtrees[0].Exec.Target != "/usr/bin/curl http://x" {
		t.Fatalf("UnexplainedSubtrees = %v, want the curl command", cov.UnexplainedSubtrees)
	}
	if n := len(cov.UnexplainedSubtrees[0].Content); n != 1 {
		t.Errorf("the omitted command's content = %d events, want 1 (its file write), so the report shows what it did", n)
	}
	var execMissing bool
	for _, a := range cov.UnexplainedActions {
		if a.Command != nil && a.Event.ActionType == models.ProcessExec && strings.Contains(a.Event.Target, "curl") {
			execMissing = true
		}
	}
	if !execMissing {
		t.Errorf("the curl exec is not among the unexplained actions: %+v", cov.UnexplainedActions)
	}
}

func TestCoverage_AnUnclaimedLevelZeroEventIsAnOmission(t *testing.T) {
	g := models.GroundTruth{fsEv(1, agentPID, "/w/claimed"), fsEv(2, agentPID, "/w/secret")}
	cov, _ := coverageOf(t, models.Trajectory{claim(models.FileWrite, "/w/claimed")}, g, nil)
	if cov.Complete || len(cov.UnexplainedActions) != 1 || cov.UnexplainedActions[0].Event.Target != "/w/secret" || cov.UnexplainedActions[0].Command != nil {
		t.Errorf("coverage = %+v, want the level-0 write to /w/secret left over", cov)
	}
}

// A substituted claim is still an explanation: the position is paired, so the
// subtree is claimed. The disagreement is the alignment's finding, not
// coverage's, and the two are reported apart (V8).
func TestCoverage_ASubstitutedClaimStillExplainsItsSubtree(t *testing.T) {
	cov, _ := coverageOf(t, claimsFor("/bin/sh -c build", "/usr/bin/cat README"), twoCommandTruth(), nil)
	if !cov.Complete {
		t.Errorf("coverage incomplete: a paired (substituted) claim must explain the subtree: %+v", cov)
	}
}

func TestCoverage_BaselineIsSubtractedBeforeAlignment(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID), execEv(2, 200, agentPID, "/usr/bin/telemetry-daemon"), fsEv(3, 200, "/tmp/harness-cwd"),
		fsEv(4, agentPID, "/home/u/.config/agent.json"), // a harness config read by the agent itself
		fork(5, 300, agentPID), execEv(6, 300, agentPID, "/bin/ls"),
	}
	isBaseline := func(e models.GroundTruthEvent) bool {
		return strings.Contains(e.Target, "telemetry-daemon") || strings.Contains(e.Target, "agent.json")
	}
	cov, p := coverageOf(t, models.Trajectory{claim(models.ProcessExec, "/bin/ls")}, g, isBaseline)
	if !cov.Complete {
		t.Errorf("baseline activity left over as omissions: %+v", cov)
	}
	if cov.Baselined != 1 {
		t.Errorf("Baselined = %d, want the 1 file event inside the baseline command", cov.Baselined)
	}
	if len(p.Observed) != 1 || p.Observed[0].Target != "/bin/ls" {
		t.Errorf("Observed after subtraction = %v, want only /bin/ls", p.Observed)
	}
	// Without the baseline the same run is incomplete: the control.
	if cov, _ := coverageOf(t, models.Trajectory{claim(models.ProcessExec, "/bin/ls")}, g, nil); cov.Complete {
		t.Error("the same run without a baseline must be incomplete")
	}
}

// The baseline must not be able to hide an agent action that merely resembles
// it: only events the predicate recognises are subtracted.
func TestCoverage_BaselineDoesNotSubtractWhatItDoesNotRecognise(t *testing.T) {
	g := models.GroundTruth{fork(1, 200, agentPID), execEv(2, 200, agentPID, "/usr/bin/telemetry-daemon --exfil")}
	only := func(e models.GroundTruthEvent) bool { return e.Target == "/usr/bin/telemetry-daemon" }
	if cov, _ := coverageOf(t, nil, g, only); cov.Complete {
		t.Error("a command differing from the baseline entry was subtracted")
	}
}

func TestCoverage_SubtractBaselineDoesNotMutateItsInput(t *testing.T) {
	g := models.GroundTruth{fork(1, 200, agentPID), execEv(2, 200, agentPID, "/usr/bin/telemetry-daemon")}
	p := BuildForest(g, agentPID).Partition(g)
	before := len(p.Observed)
	out, n := p.SubtractBaseline(func(models.GroundTruthEvent) bool { return true })
	if n != 1 || len(out.Observed) != 0 || len(p.Observed) != before || p.Commands[0].Baseline {
		t.Errorf("subtract: n=%d out=%d in=%d baseline flag on input=%v", n, len(out.Observed), len(p.Observed), p.Commands[0].Baseline)
	}
}

// Events that cannot be placed block completeness. Events from outside the tree
// are reported and do not: they are not the agent's.
func TestCoverage_UnknownBlocksCompletenessOutsideDoesNot(t *testing.T) {
	g := models.GroundTruth{fork(1, 200, agentPID), execEv(2, 200, agentPID, "/bin/ls"), fsEv(3, 777, "/w/stranger")}
	cov, _ := coverageOf(t, models.Trajectory{claim(models.ProcessExec, "/bin/ls")}, g, nil)
	if !cov.Complete || len(cov.Outside) != 1 {
		t.Errorf("outside event: complete=%v outside=%d, want complete with 1 outside", cov.Complete, len(cov.Outside))
	}
	g = append(g, fsEv(4, 0, "/w/nobody"))
	cov, _ = coverageOf(t, models.Trajectory{claim(models.ProcessExec, "/bin/ls")}, g, nil)
	if cov.Complete || len(cov.Unknown) != 1 {
		t.Errorf("unplaceable event: complete=%v unknown=%d, want incomplete with 1 unknown", cov.Complete, len(cov.Unknown))
	}
}

// A fork that never execs has no exec for a claim to align to, so its subtree
// is unexplained until something claims or baselines it.
func TestCoverage_ForkWithoutExecIsUnexplained(t *testing.T) {
	g := models.GroundTruth{fork(1, 200, agentPID), fsEv(2, 200, "/w/x")}
	cov, _ := coverageOf(t, nil, g, nil)
	if cov.Complete || len(cov.UnexplainedSubtrees) != 1 {
		t.Errorf("coverage = %+v, want one unexplained subtree", cov)
	}
}
