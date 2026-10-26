package verification

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// aliasScope is an fs_scope record whose mount table has a tmpfs (0:40)
// mounted whole at /fs, where the probe names it, and its subdirectory /src
// bound at /alias, on a root filesystem the probe names at /. changed is the
// record's mount_table_changed.
func aliasScope(changed *bool) *models.FSScope {
	return &models.FSScope{
		Rule: "test", MountTableChanged: changed,
		Filesystems: []models.FSMounts{
			{Device: "8:1", FSType: "ext4", Mounts: []models.Mount{{ID: 20, Parent: 1, Root: "/", Point: "/", Names: true}}},
			{Device: "0:40", FSType: "tmpfs", Mounts: []models.Mount{
				{ID: 21, Parent: 20, Root: "/", Point: "/fs", Names: true},
				{ID: 22, Parent: 20, Root: "/src", Point: "/alias"},
			}},
		},
	}
}

func boolp(b bool) *bool { return &b }

// V-46 in the verifier: a file claim through a bind alias pairs with the
// event the probe named through its own mount when the capture's mount table
// proves both reach the same file; the pair keeps the claim's path and the
// probe's name. An alias the table cannot prove stays a target substitution.
func TestVerify_AClaimThroughAProvenAliasIsCorroborated(t *testing.T) {
	g := models.GroundTruth{withHash(agentEv(0, models.FileWrite, "/fs/src/a.txt"), nil, sp("h"))}
	claims := models.Trajectory{withClaimHash(claimAt(0, models.FileWrite, "/alias/a.txt"), nil, sp("h"))}
	verify := func(s *models.FSScope, claims models.Trajectory) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), FSScope: s})
	}

	v := verify(aliasScope(boolp(false)), claims)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Corroborated) != 1 || v.Corroborated[0].Entry.Target != "/alias/a.txt" || v.Corroborated[0].Event.Target != "/fs/src/a.txt" {
		t.Errorf("corroborated %+v, want the claim's path paired with the probe's name", v.Corroborated)
	}

	for _, c := range []struct {
		name   string
		scope  *models.FSScope
		claims models.Trajectory
	}{
		{"no record", nil, claims},
		{"a table that changed", aliasScope(boolp(true)), claims},
		{"a table whose change is unknown", aliasScope(nil), claims},
		{"another file under the alias", aliasScope(boolp(false)), models.Trajectory{withClaimHash(claimAt(0, models.FileWrite, "/alias/b.txt"), nil, sp("h"))}},
		{"the same suffix elsewhere", aliasScope(boolp(false)), models.Trajectory{withClaimHash(claimAt(0, models.FileWrite, "/other/src/a.txt"), nil, sp("h"))}},
		{"a relative path", aliasScope(boolp(false)), models.Trajectory{withClaimHash(claimAt(0, models.FileWrite, "alias/a.txt"), nil, sp("h"))}},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := verify(c.scope, c.claims)
			wantOutcome(t, v, OutcomeNotFaithful)
			if len(v.Mismatched) != 1 || v.Mismatched[0].Diffs[0] != DiffTarget || len(v.Corroborated) != 0 {
				t.Errorf("mismatched %+v, corroborated %d; want one target substitution", v.Mismatched, len(v.Corroborated))
			}
		})
	}

	t.Run("the content is still compared", func(t *testing.T) {
		v := verify(aliasScope(boolp(false)), models.Trajectory{withClaimHash(claimAt(0, models.FileWrite, "/alias/a.txt"), nil, sp("other"))})
		if len(v.Mismatched) != 1 || v.Mismatched[0].Diffs[0] != DiffOutputHash {
			t.Errorf("mismatched %+v, want the output hash only", v.Mismatched)
		}
	})
}

// The paths a claim names are compared with observed names, so a claim
// through an alias keeps the baseline's event on the probe's name in the
// sequence for itself (V-30), and a harness-implied claim through an alias
// pairs with the harness's open of the probe's name, witnessed by its
// command's open of it (V-33).
func TestVerify_AnAliasClaimKeepsItsBaselineEventAndWitnessesItsImpliedOpen(t *testing.T) {
	scope := aliasScope(boolp(false))
	open := agentEv(0, models.FileOpen, "/fs/src/a.txt")
	rule := func(e models.GroundTruthEvent) bool { return e == open }
	v := Verify(Input{Claims: models.Trajectory{claimAt(0, models.FileOpen, "/alias/a.txt")}, Ground: models.GroundTruth{open},
		RootPID: agentPID, Coverage: completeCov(), FSScope: scope, Baseline: rule})
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Corroborated) != 1 || len(v.CorroboratedHarnessShared) != 1 {
		t.Errorf("corroborated %d, shared %d; want the claim paired with the baseline's open", len(v.Corroborated), len(v.CorroboratedHarnessShared))
	}

	const cmd = "cat /alias/a.txt"
	g := models.GroundTruth{
		fork(1, 200, agentPID), execEv(2, 200, agentPID, cmd),
		{Timestamp: at(3), ActionType: models.FileOpen, Target: "/fs/src/a.txt", PID: 200},
		exitEv(4, 200, agentPID, cmd),
		agentEv(5, models.FileOpen, "/fs/src/a.txt"),
	}
	implied := claimAt(5, models.FileOpen, "/alias/a.txt")
	implied.ImpliedBy = cmd
	claims := append(claimsFor(cmd), implied)
	v = Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), FSScope: scope})
	if len(v.HarnessImplied) != 1 || len(v.Unrecorded) != 0 {
		t.Errorf("harness implied %v, unrecorded %v; want the implied claim through the alias paired", v.HarnessImplied, v.Unrecorded)
	}
	v = Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), FSScope: aliasScope(boolp(true))})
	if len(v.HarnessImplied) != 0 || len(v.Unrecorded) != 1 {
		t.Errorf("unproven table: harness implied %v, unrecorded %v; want the open unrecorded", v.HarnessImplied, v.Unrecorded)
	}
}
