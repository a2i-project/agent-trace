package verification

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func hashedOpen(ms int, pid uint32, path, hash string) models.GroundTruthEvent {
	e := openBy(ms, pid, path)
	if hash != "" {
		e.InputHash = models.StringPtr(hash)
	}
	return e
}

// readThenEdit is what the second long pilot of Claude Code 2.1.306 showed:
// the agent's process opens a file for a Read, opens /etc/hosts for its own
// telemetry, then opens the file again for the Edit after it. The claims
// join the Read's open and the Edit's into one (collapseOpenClaims); the
// baseline explains the /etc/hosts open.
func readThenEdit() (models.Trajectory, models.GroundTruth, Baseline) {
	open := claimAt(5, models.FileOpen, "/w/f")
	end := at(40)
	open.End = &end
	g := models.GroundTruth{
		hashedOpen(10, agentPID, "/w/f", "sha256:a"),
		openBy(20, agentPID, "/etc/hosts"),
		hashedOpen(30, agentPID, "/w/f", "sha256:a"),
	}
	baseline := func(e models.GroundTruthEvent) bool { return e.Target == "/etc/hosts" }
	return models.Trajectory{open}, g, baseline
}

// With the declaration the run the baselined open broke is one access again
// and the run is FAITHFUL, the folded open listed; without it the second
// open is Unrecorded, as before V-49.
func TestVerify_ABaselinedEventBetweenTwoOpensOfAFileLeavesOneAccess(t *testing.T) {
	tr, g, b := readThenEdit()
	in := Input{Claims: tr, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: b,
		Options: Options{IgnoreExits: true, CollapseOpenRuns: true}}
	v := Verify(in)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.RepeatedOpens) != 1 || !v.RepeatedOpens[0].Timestamp.Equal(at(30)) {
		t.Errorf("repeated opens %v, want the open at 30 ms", v.RepeatedOpens)
	}
	if len(v.Corroborated) != 1 || !v.Corroborated[0].Event.Timestamp.Equal(at(10)) {
		t.Errorf("corroborated %v, want the first open", v.Corroborated)
	}

	in.Options.CollapseOpenRuns = false
	v = Verify(in)
	if v.Outcome != OutcomeNotFaithful || len(v.Unrecorded) != 1 || len(v.RepeatedOpens) != 0 {
		t.Errorf("without the declaration: outcome %s, unrecorded %v, repeated %v", v.Outcome, v.Unrecorded, v.RepeatedOpens)
	}
}

// Only a run the set-asides alone broke is folded: the open must be of the
// same path, ambiguity and content by the same process, with no file event
// of that process left between. Commands, other lanes and the harness's own
// files do not break a run, as in the adapter's collapse.
func TestCollapseOpenRuns(t *testing.T) {
	owned := func(p string) bool { return p == "/h/state" }
	cmd := &Command{}
	ambiguous := openBy(30, agentPID, "/w")
	ambiguous.PathIsAmbiguous = true
	for _, tc := range []struct {
		name     string
		observed models.GroundTruth
		owner    []*Command
		folded   int
	}{
		{"adjacent opens", models.GroundTruth{hashedOpen(10, agentPID, "/w/f", "h"), hashedOpen(30, agentPID, "/w/f", "h")}, nil, 1},
		{"a run of three", models.GroundTruth{openBy(10, agentPID, "/w/f"), openBy(20, agentPID, "/w/f"), openBy(30, agentPID, "/w/f")}, nil, 2},
		{"other content", models.GroundTruth{hashedOpen(10, agentPID, "/w/f", "h"), hashedOpen(30, agentPID, "/w/f", "i")}, nil, 0},
		{"one hash missing", models.GroundTruth{hashedOpen(10, agentPID, "/w/f", "h"), openBy(30, agentPID, "/w/f")}, nil, 0},
		{"another file between", models.GroundTruth{openBy(10, agentPID, "/w/f"), openBy(20, agentPID, "/w/g"), openBy(30, agentPID, "/w/f")}, nil, 0},
		{"a write between", models.GroundTruth{openBy(10, agentPID, "/w/f"), {Timestamp: at(20), ActionType: models.FileWrite, Target: "/w/f", PID: agentPID}, openBy(30, agentPID, "/w/f")}, nil, 0},
		{"another process", models.GroundTruth{openBy(10, agentPID, "/w/f"), openBy(30, agentPID+1, "/w/f")}, nil, 0},
		{"no pid", models.GroundTruth{openBy(10, 0, "/w/f"), openBy(30, 0, "/w/f")}, nil, 0},
		{"ambiguous after named", models.GroundTruth{openBy(10, agentPID, "/w"), ambiguous}, nil, 0},
		{"a harness file between", models.GroundTruth{openBy(10, agentPID, "/w/f"), openBy(20, agentPID, "/h/state"), openBy(30, agentPID, "/w/f")}, nil, 1},
		{"a connection between", models.GroundTruth{openBy(10, agentPID, "/w/f"), {Timestamp: at(20), ActionType: models.NetConnect, Target: "h", PID: agentPID}, openBy(30, agentPID, "/w/f")}, nil, 1},
		{"a command's exec between", models.GroundTruth{openBy(10, agentPID, "/w/f"), execEv(20, 200, agentPID, "ls"), openBy(30, agentPID, "/w/f")}, []*Command{nil, cmd, nil}, 1},
		{"opens of the harness's file", models.GroundTruth{openBy(10, agentPID, "/h/state"), openBy(30, agentPID, "/h/state")}, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := tc.owner
			if owner == nil {
				owner = make([]*Command, len(tc.observed))
			}
			p := Partition{Observed: tc.observed, Owner: owner}
			out, folded := p.collapseOpenRuns(owned)
			if len(folded) != tc.folded || len(out.Observed) != len(tc.observed)-tc.folded || len(out.Owner) != len(out.Observed) {
				t.Errorf("folded %v, kept %d events and %d owners, want %d folded", folded, len(out.Observed), len(out.Owner), tc.folded)
			}
		})
	}
}
