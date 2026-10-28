package verification

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// impliedOpen is a harness-implied claim (V-33): the open of path the harness
// may make after the Bash command cmd, over the call's interval [from, to].
func impliedOpen(from, to int, path, cmd string) models.TrajectoryEntry {
	end := at(to)
	return models.TrajectoryEntry{Timestamp: at(from), End: &end, ActionType: models.FileOpen, Target: path, ImpliedBy: cmd, Tool: "Bash"}
}

func openBy(ms int, pid uint32, path string) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: at(ms), ActionType: models.FileOpen, Target: path, PID: pid}
}

// catRun is a Bash call of `cat f`: the command at level 1, its cat child
// opening the file, and the agent's process opening it again afterwards (the
// harness recording file state), as the shapes capture shows it.
func catRun() models.GroundTruth {
	return models.GroundTruth{
		fork(10, 200, agentPID), execEv(11, 200, agentPID, "cat f"),
		fork(12, 201, 200), execEv(13, 201, 200, "/usr/bin/cat f"),
		openBy(14, 201, "/w/f"),
		openBy(20, agentPID, "/w/f"),
	}
}

func catClaims() models.Trajectory {
	bash := claimAt(5, models.ProcessExec, "cat f")
	end := at(30)
	bash.End = &end
	return models.Trajectory{bash, impliedOpen(5, 30, "/w/f", "cat f")}
}

func verifyImplied(tr models.Trajectory, g models.GroundTruth) Verdict {
	return Verify(Input{Claims: tr, Ground: g, RootPID: agentPID, Coverage: completeCov(), Options: Options{IgnoreExits: true}})
}

// The harness's read pairs with the implied claim: reported as harness
// implied, not as a corroboration of the agent, and the run is FAITHFUL.
func TestVerify_TheHarnessReadAfterACatIsHarnessImplied(t *testing.T) {
	v := verifyImplied(catClaims(), catRun())
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Corroborated) != 1 || v.Corroborated[0].Entry.ActionType != models.ProcessExec {
		t.Errorf("corroborated %v, want only the Bash claim", v.Corroborated)
	}
	if len(v.HarnessImplied) != 1 || v.HarnessImplied[0].Event.PID != agentPID || len(v.HarnessImpliedUnpaired) != 0 {
		t.Errorf("harness implied %v, unpaired %v, want the agent process's open", v.HarnessImplied, v.HarnessImpliedUnpaired)
	}
	// Without the implied claim the same open is an omission.
	v = verifyImplied(catClaims()[:1], catRun())
	if v.Outcome != OutcomeNotFaithful || len(v.Unrecorded) != 1 {
		t.Errorf("without the implied claim: outcome %s, unrecorded %v", v.Outcome, v.Unrecorded)
	}
}

// The harness does not always read (the file is already known, or it is not
// a regular file), so an implied claim left unpaired costs nothing: no
// finding, not Unwitnessed, and FAITHFUL.
func TestVerify_AnUnpairedImpliedClaimCostsNothing(t *testing.T) {
	g := catRun()[:5]
	v := verifyImplied(catClaims(), g)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Unwitnessed) != 0 || len(v.HarnessImplied) != 0 || len(v.HarnessImpliedUnpaired) != 1 || v.Ambiguous {
		t.Errorf("unwitnessed %v, implied %v, unpaired %v, ambiguous %v", v.Unwitnessed, v.HarnessImplied, v.HarnessImpliedUnpaired, v.Ambiguous)
	}
}

// An implied claim pairs only with an open of exactly its path, inside its
// interval, after the command it names opened that path. Every other event it
// could meet stays as it would be without it: an Unrecorded finding, never a
// Mismatched pair.
func TestVerify_AnImpliedClaimAbsorbsOnlyTheExactOpenTheCommandMadeFirst(t *testing.T) {
	type mutate func(g models.GroundTruth) models.GroundTruth
	set := func(i int, f func(*models.GroundTruthEvent)) mutate {
		return func(g models.GroundTruth) models.GroundTruth { f(&g[i]); return g }
	}
	for name, m := range map[string]mutate{
		"a write of the file": set(5, func(e *models.GroundTruthEvent) { e.ActionType = models.FileWrite }),
		"a close of the file": set(5, func(e *models.GroundTruthEvent) { e.ActionType = models.FileClose }),
		"a rename":            set(5, func(e *models.GroundTruthEvent) { e.ActionType = models.FileRename }),
		"a delete":            set(5, func(e *models.GroundTruthEvent) { e.ActionType = models.FileDelete }),
		"an open of another file": func(g models.GroundTruth) models.GroundTruth {
			g[5].Target = "/w/secret"
			return g
		},
		"an open of the same path written otherwise": set(5, func(e *models.GroundTruthEvent) { e.Target = "/w/./f" }),
		"a directory record of the open": set(5, func(e *models.GroundTruthEvent) {
			e.Target, e.PathIsAmbiguous = "/w", true
		}),
		"an open outside the call's interval": set(5, func(e *models.GroundTruthEvent) { e.Timestamp = at(40) }),
		"an open before the command's":        set(5, func(e *models.GroundTruthEvent) { e.Timestamp = at(13) }),
		"no open by the command": func(g models.GroundTruth) models.GroundTruth {
			g[4].Target = "/w/other"
			return g
		},
		"the open made by another command": func(g models.GroundTruth) models.GroundTruth {
			g[1].Target = "cat g"
			return g
		},
		"a stated content the event contradicts": func(g models.GroundTruth) models.GroundTruth {
			g[5].InputHash = sp("sha256:x")
			return g
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := m(catRun())
			tr := catClaims()
			if name == "a stated content the event contradicts" {
				tr[1].InputHash = sp("sha256:y")
			}
			if name == "the open made by another command" {
				tr[0].Target = "cat g"
			}
			v := verifyImplied(tr, g)
			if len(v.HarnessImplied) != 0 || len(v.Mismatched) != 0 || len(v.Unwitnessed) != 0 || len(v.HarnessImpliedUnpaired) != 1 {
				t.Fatalf("implied %v mismatched %v unwitnessed %v unpaired %v", v.HarnessImplied, v.Mismatched, v.Unwitnessed, v.HarnessImpliedUnpaired)
			}
			if v.Outcome != OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Findings() != 1 {
				t.Errorf("outcome %s, findings %d, unrecorded %v: the event must stay an omission", v.Outcome, v.Findings(), v.Unrecorded)
			}
		})
	}
}

// A marker on anything but an open is ignored: the claim is the agent's like
// any other and is Unwitnessed when nothing pairs with it.
func TestVerify_AnImpliedMarkerOnAnotherTypeIsIgnored(t *testing.T) {
	tr := catClaims()
	tr[1].ActionType = models.FileWrite
	v := verifyImplied(tr, catRun()[:5])
	if len(v.Unwitnessed) != 1 || len(v.HarnessImpliedUnpaired) != 0 {
		t.Errorf("unwitnessed %v, unpaired implied %v, want the write Unwitnessed", v.Unwitnessed, v.HarnessImpliedUnpaired)
	}
}

// An ordinary claim of the same open wins it: leaving an ordinary claim
// unpaired costs 2, an implied one nothing, so the agent's Read pairs with the
// open whichever comes first in the trajectory, and the reading is unique.
func TestAlign_AnOrdinaryClaimWinsAnOpenOverAnImpliedOne(t *testing.T) {
	read := claimAt(5, models.FileOpen, "/w/f")
	for name, c := range map[string]models.Trajectory{
		"implied first": {impliedOpen(5, 30, "/w/f", "cat f"), read},
		"implied last":  {read, impliedOpen(5, 30, "/w/f", "cat f")},
	} {
		a := laneOf(t, mustAlign(t, c, models.GroundTruth{openBy(20, agentPID, "/w/f")}), LaneFS)
		if a.Ambiguous || a.Optimal != 1 {
			t.Errorf("%s: ambiguous %v, optimal %d", name, a.Ambiguous, a.Optimal)
		}
		for _, e := range a.Edits {
			if e.Kind == EditMatch && implied(*e.Claim) {
				t.Errorf("%s: the implied claim took the open from the Read: %+v", name, a.Edits)
			}
		}
	}
}

// An unpaired implied claim and an unpaired event next to each other are one
// reading, whichever order the steps could be taken in, so they never make a
// lane ambiguous; two implied claims that could each take one open are two
// readings, and the interval chooses between them when the calls' intervals
// differ.
func TestAlign_ImpliedClaimsCountReadingsNotPaths(t *testing.T) {
	a := laneOf(t, mustAlign(t, models.Trajectory{impliedOpen(0, 30, "/w/f", "cat f")}, models.GroundTruth{openBy(20, agentPID, "/w/g")}), LaneFS)
	if a.Ambiguous || a.Optimal != 1 || len(a.Edits) != 2 {
		t.Errorf("an unpaired implied claim beside an unpaired event: optimal %d, edits %+v", a.Optimal, a.Edits)
	}
	inBlockToo := inBlock("m", impliedOpen(0, 30, "/w/f", "cat f"), claimAt(0, models.FileOpen, "/w/h"))
	a = laneOf(t, mustAlign(t, inBlockToo, models.GroundTruth{openBy(20, agentPID, "/w/g"), openBy(21, agentPID, "/w/h")}), LaneFS)
	if a.Ambiguous || a.Optimal != 1 {
		t.Errorf("in a block: optimal %d, edits %+v", a.Optimal, a.Edits)
	}
	two := models.Trajectory{impliedOpen(0, 100, "/w/f", "cat f"), impliedOpen(0, 100, "/w/f", "cat f")}
	two[1].Timestamp = at(1)
	a = laneOf(t, mustAlign(t, two, models.GroundTruth{openBy(20, agentPID, "/w/f")}), LaneFS)
	if !a.Ambiguous || a.Optimal != 2 {
		t.Errorf("two implied claims for one open: optimal %d, want 2", a.Optimal)
	}
	two[1] = impliedOpen(50, 100, "/w/f", "cat f")
	a = laneOf(t, mustAlign(t, two, models.GroundTruth{openBy(20, agentPID, "/w/f")}), LaneFS)
	if a.Ambiguous || a.Optimal != 1 || a.Edits[0].Kind != EditMatch {
		t.Errorf("the open inside the first call only: optimal %d, edits %+v", a.Optimal, a.Edits)
	}
}

// An implied claim belongs to the block of the call that implied it (V-32):
// in the shapes capture's block, a Bash `cat fast.txt` and a Read whose events
// came in the other order, both pair.
func TestVerify_AnImpliedClaimMovesWithItsBlock(t *testing.T) {
	g := models.GroundTruth{
		fork(10, 200, agentPID), execEv(11, 200, agentPID, "cat f"),
		fork(12, 201, 200), execEv(13, 201, 200, "/usr/bin/cat f"),
		openBy(14, 201, "/w/f"),
		openBy(15, agentPID, "/w/read"),
		openBy(20, agentPID, "/w/f"),
	}
	tr := catClaims()
	tr = append(tr, claimAt(6, models.FileOpen, "/w/read"))
	for i := range tr {
		tr[i].BlockID = "msg"
	}
	v := verifyImplied(tr, g)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Corroborated) != 2 || len(v.HarnessImplied) != 1 || v.Ambiguous {
		t.Errorf("corroborated %d, implied %d, ambiguous %v", len(v.Corroborated), len(v.HarnessImplied), v.Ambiguous)
	}
	// Outside the block the order is fixed and the implied claim cannot reach
	// back over the Read's open: it stays unpaired and the open is
	// Unrecorded, as before V-33.
	for i := range tr {
		tr[i].BlockID = ""
	}
	tr[1], tr[2] = tr[2], tr[1]
	tr[1].Timestamp = at(6)
	g[5], g[6] = g[6], g[5]
	g[5].Timestamp, g[6].Timestamp = at(15), at(20)
	v = verifyImplied(tr, g)
	if len(v.HarnessImplied) != 0 || len(v.Unrecorded) != 1 {
		t.Errorf("outside a block: implied %v, unrecorded %v", v.HarnessImplied, v.Unrecorded)
	}
}

// An implied claim names no path for V-30 and V-24: a baseline event on its
// path is subtracted as before, and a harness-owned one is set aside, so the
// claim cannot keep an event in the sequence that would otherwise not be
// there. It stays unpaired.
func TestVerify_AnImpliedClaimKeepsNoBaselineOrHarnessEvent(t *testing.T) {
	baseline := func(e models.GroundTruthEvent) bool {
		return e.ActionType == models.FileOpen && e.Target == "/w/f" && e.PID == agentPID
	}
	v := Verify(Input{Claims: catClaims(), Ground: catRun(), RootPID: agentPID, Coverage: completeCov(), Baseline: baseline, Options: Options{IgnoreExits: true}})
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.HarnessImplied) != 0 || len(v.HarnessImpliedUnpaired) != 1 || len(v.Unrecorded) != 0 {
		t.Errorf("implied %v, unpaired %v, unrecorded %v", v.HarnessImplied, v.HarnessImpliedUnpaired, v.Unrecorded)
	}
	owned := func(p string) bool { return p == "/w/f" }
	v = Verify(Input{Claims: catClaims(), Ground: catRun(), RootPID: agentPID, Coverage: completeCov(), Options: Options{IgnoreExits: true, HarnessOwned: owned}})
	if v.Outcome != OutcomeInconclusive || len(v.UnexplainedHarness) != 1 || len(v.HarnessImplied) != 0 {
		t.Errorf("outcome %s, unexplained harness %v, implied %v", v.Outcome, v.UnexplainedHarness, v.HarnessImplied)
	}
}

// An implied claim on a path the capture could not observe is not set aside
// as out of scope, which would block FAITHFUL: it is listed as unpaired.
func TestVerify_AnOutOfScopeImpliedClaimIsOnlyListed(t *testing.T) {
	tr := catClaims()
	tr[1].Target = "/etc/hosts"
	v := Verify(Input{Claims: tr, Ground: catRun()[:5], RootPID: agentPID, Coverage: completeCov(), Workspace: "/w", Options: Options{IgnoreExits: true}})
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.OutOfScope) != 0 || len(v.HarnessImpliedUnpaired) != 1 {
		t.Errorf("out of scope %v, unpaired implied %v", v.OutOfScope, v.HarnessImpliedUnpaired)
	}
}

// The marker has no JSON form: a trajectory read from JSON that names it is
// refused, and an entry written to JSON never carries it, so a normalized
// trajectory cannot hold a harness-implied claim (V-33).
func TestTheImpliedMarkerHasNoJSONForm(t *testing.T) {
	data, err := json.Marshal(models.Trajectory{impliedOpen(0, 1, "/w/f", "cat f")})
	if err != nil || strings.Contains(string(data), "cat f") || strings.Contains(strings.ToLower(string(data)), "implied") {
		t.Errorf("marshalled %s, %v: the marker must not be written", data, err)
	}
	if _, err := models.ParseTrajectory([]byte(`[{"timestamp":"2026-10-13T00:00:00Z","action_type":"file_open","target":"/w/f","implied_by":"cat f"}]`)); err == nil {
		t.Error("a trajectory naming implied_by was accepted")
	}
	tr, err := models.ParseTrajectory([]byte(`[{"timestamp":"2026-10-13T00:00:00Z","action_type":"file_open","target":"/w/f","ImpliedBy":"cat f","Implied_By":"x"}]`))
	if err != nil || len(tr) != 1 || tr[0].ImpliedBy != "" {
		t.Errorf("another spelling must not set the marker: %+v, %v", tr, err)
	}
}

// V-33 against the independent brute force of V-32: random lanes holding
// blocks and harness-implied claims (refused every pair but an exact open
// inside their interval, free when unpaired). The reading shown has the
// minimum cost and fewest interval violations, and Optimal counts the
// distinct minimum-cost pairings, so an unpaired implied claim beside an
// unpaired event is one reading, however the steps are ordered.
func TestAlign_ImpliedClaimsAgreeWithBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(33))
	targets := []string{"a", "b", "c"}
	types := []models.ActionType{models.FileOpen, models.FileWrite}
	blocks := []string{"", "m1", "m1", "m2"}
	sawImpliedPaired, sawImpliedUnpairedBesideDeletion, sawAmbiguous := 0, 0, 0
	for trial := 0; trial < 1500; trial++ {
		var c models.Trajectory
		for i, n := 0, 1+rng.Intn(5); i < n; i++ {
			e := models.TrajectoryEntry{Timestamp: t0.Add(time.Duration(rng.Intn(10)) * time.Second), ActionType: types[rng.Intn(2)], Target: targets[rng.Intn(3)], BlockID: blocks[rng.Intn(len(blocks))]}
			if rng.Intn(2) == 0 {
				e.ActionType, e.ImpliedBy = models.FileOpen, "cmd"
			}
			if rng.Intn(3) > 0 {
				end := e.Timestamp.Add(time.Duration(rng.Intn(4)) * time.Second)
				e.End = &end
			}
			c = append(c, e)
		}
		var o models.GroundTruth
		for i, n := 0, rng.Intn(6); i < n; i++ {
			o = append(o, models.GroundTruthEvent{Timestamp: t0.Add(time.Duration(rng.Intn(12)) * time.Second), ActionType: types[rng.Intn(2)], Target: targets[rng.Intn(3)]})
		}
		wantCost, wantPairings, wantViol := bruteForceBlocks(c, o)
		as, err := Align(c, o, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(o) == 0 && !hasFS(c) {
			continue
		}
		a := laneOf(t, as, LaneFS)
		runOf := runsOf(c)
		cost, viol, nextEvent := 0, 0, 0
		var pairs [][2]int
		deletions, unpairedImplied := 0, 0
		for _, e := range a.Edits {
			if e.EventIndex >= 0 {
				if e.EventIndex != nextEvent {
					t.Fatalf("trial %d: events out of order: %+v", trial, a.Edits)
				}
				nextEvent++
			}
			switch e.Kind {
			case EditInsertion:
				cost += insertCost(*e.Claim)
				if implied(*e.Claim) {
					unpairedImplied++
				}
			case EditDeletion:
				cost += costIndel
				deletions++
			default:
				pc, ok := pairCostOf(*e.Claim, *e.Event, false, Options{})
				if !ok {
					t.Fatalf("trial %d: a refused pair was taken: %+v", trial, e)
				}
				if implied(*e.Claim) {
					sawImpliedPaired++
					if e.Kind != EditMatch || e.OutsideInterval {
						t.Fatalf("trial %d: an implied claim paired as %v outside=%v", trial, e.Kind, e.OutsideInterval)
					}
				}
				cost += pc
				if e.OutsideInterval {
					viol++
				}
				pairs = append(pairs, [2]int{e.ClaimIndex, e.EventIndex})
			}
		}
		if unpairedImplied > 0 && deletions > 0 {
			sawImpliedUnpairedBesideDeletion++
		}
		if cost != wantCost || viol != wantViol {
			t.Fatalf("trial %d: reading costs (%d, %d), brute force (%d, %d)\nclaims %+v\nevents %+v", trial, cost, viol, wantCost, wantViol, c, o)
		}
		if !wantPairings[pairingKey(classes(c, runOf), pairs)] {
			t.Fatalf("trial %d: the reading shown is not a minimum-cost pairing", trial)
		}
		if int(a.Optimal) != len(wantPairings) || a.Ambiguous != (len(wantPairings) > 1) {
			t.Fatalf("trial %d: Optimal = %d, brute force finds %d pairings %v\nclaims %+v\nevents %+v\nedits %+v", trial, a.Optimal, len(wantPairings), wantPairings, c, o, a.Edits)
		}
		if a.Ambiguous {
			sawAmbiguous++
		}
	}
	t.Logf("implied claims paired %d times, unpaired beside a deletion in %d lanes, %d ambiguous lanes", sawImpliedPaired, sawImpliedUnpairedBesideDeletion, sawAmbiguous)
	if sawImpliedPaired < 200 || sawImpliedUnpairedBesideDeletion < 200 || sawAmbiguous < 30 {
		t.Errorf("too few cases exercised: %d paired, %d beside a deletion, %d ambiguous", sawImpliedPaired, sawImpliedUnpairedBesideDeletion, sawAmbiguous)
	}
}

func hasFS(c models.Trajectory) bool {
	for _, e := range c {
		if LaneOf(e.ActionType) == LaneFS {
			return true
		}
	}
	return false
}
