package verification

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// grepRun is a Grep of one file as Claude Code 2.1.306 runs it (I-69): the
// agent's own process opens the file, then starts its ripgrep, which reads
// the file through the descriptor it inherited and is seen opening the same
// path.
func grepRun() models.GroundTruth {
	return models.GroundTruth{
		openBy(10, agentPID, "/w/f"),
		fork(11, 200, agentPID), execEv(12, 200, agentPID, "search:grep"),
		openBy(14, 200, "/w/f"),
	}
}

func grepClaims() models.Trajectory {
	grep := claimAt(5, models.ProcessExec, "search:grep")
	end := at(30)
	grep.End = &end
	open := impliedOpen(5, 30, "/w/f", "search:grep")
	open.ImpliedBefore = true
	return models.Trajectory{grep, open}
}

// The harness's open before the search pairs with a claim marked
// ImpliedBefore (V-48): the command's open of the same path comes after it.
func TestVerify_TheHarnessOpenBeforeAGrepIsHarnessImplied(t *testing.T) {
	v := verifyImplied(grepClaims(), grepRun())
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.HarnessImplied) != 1 || v.HarnessImplied[0].Event.PID != agentPID || len(v.HarnessImpliedUnpaired) != 0 {
		t.Errorf("harness implied %v, unpaired %v, want the agent process's open", v.HarnessImplied, v.HarnessImpliedUnpaired)
	}
	// Without the marker the witness is read after the command, and the
	// command opened the file only after the harness did: an omission.
	tr := grepClaims()
	tr[1].ImpliedBefore = false
	v = verifyImplied(tr, grepRun())
	if v.Outcome != OutcomeNotFaithful || len(v.Unrecorded) != 1 || len(v.HarnessImplied) != 0 {
		t.Errorf("without ImpliedBefore: outcome %s, unrecorded %v, implied %v", v.Outcome, v.Unrecorded, v.HarnessImplied)
	}
}

// A claim marked ImpliedBefore absorbs only an open the command's own open
// of the same path follows; everything else stays an omission.
func TestVerify_AnImpliedBeforeClaimNeedsTheCommandsLaterOpen(t *testing.T) {
	for name, m := range map[string]func(models.GroundTruth) models.GroundTruth{
		"the command opened the file before the harness": func(g models.GroundTruth) models.GroundTruth {
			g[0].Timestamp, g[3].Timestamp = at(15), at(14)
			g[0], g[3] = g[3], g[0]
			return g
		},
		"the command opened another file": func(g models.GroundTruth) models.GroundTruth {
			g[3].Target = "/w/other"
			return g
		},
		"another command opened the file": func(g models.GroundTruth) models.GroundTruth {
			g[2].Target = "cat f"
			return g
		},
		"the harness opened another file": func(g models.GroundTruth) models.GroundTruth {
			g[0].Target = "/w/secret"
			return g
		},
		"the harness's open is outside the call": func(g models.GroundTruth) models.GroundTruth {
			g[0].Timestamp = at(2)
			return g
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := m(grepRun())
			tr := grepClaims()
			if name == "another command opened the file" {
				tr[0].Target = "cat f"
			}
			v := verifyImplied(tr, g)
			if len(v.HarnessImplied) != 0 || len(v.Mismatched) != 0 || len(v.Unwitnessed) != 0 || len(v.HarnessImpliedUnpaired) != 1 {
				t.Fatalf("implied %v mismatched %v unwitnessed %v unpaired %v", v.HarnessImplied, v.Mismatched, v.Unwitnessed, v.HarnessImpliedUnpaired)
			}
			if v.Outcome != OutcomeNotFaithful || len(v.Unrecorded) == 0 {
				t.Errorf("outcome %s, unrecorded %v: the harness's open must stay an omission", v.Outcome, v.Unrecorded)
			}
		})
	}
}

// A Grep over a directory: the harness's open of the directory is not
// recorded and ripgrep reads the files, so the claim stays unpaired, which
// costs nothing.
func TestVerify_AnImpliedBeforeClaimLeftUnpairedCostsNothing(t *testing.T) {
	g := grepRun()[1:3]
	v := verifyImplied(grepClaims(), g)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.HarnessImpliedUnpaired) != 1 || len(v.Unwitnessed) != 0 {
		t.Errorf("unpaired %v, unwitnessed %v", v.HarnessImpliedUnpaired, v.Unwitnessed)
	}
}

// Like ImpliedBy, the marker has no JSON form and a trajectory naming it is
// refused.
func TestTheImpliedBeforeMarkerHasNoJSONForm(t *testing.T) {
	if _, err := models.ParseTrajectory([]byte(`[{"timestamp":"2026-10-13T00:00:00Z","action_type":"file_open","target":"/w/f","implied_before":true}]`)); err == nil {
		t.Error("a trajectory naming implied_before was accepted")
	}
}
