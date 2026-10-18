package verification

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func sp(s string) *string { return &s }

// completeCov is a capture that lost nothing on the three probes.
func completeCov() *models.Coverage {
	return cov(map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}, "net": {Ran: true}})
}

// run verifies with the agent rooted at agentPID and a complete capture.
func run(claims models.Trajectory, g models.GroundTruth) Verdict {
	return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov()})
}

// agentEv is an event the agent process itself caused (level 0).
func agentEv(ms int, typ models.ActionType, target string) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: at(ms), ActionType: typ, Target: target, PID: agentPID}
}

func claimAt(ms int, typ models.ActionType, target string) models.TrajectoryEntry {
	return models.TrajectoryEntry{Timestamp: at(ms), ActionType: typ, Target: target}
}

func wantOutcome(t *testing.T, v Verdict, want Outcome) {
	t.Helper()
	if v.Outcome != want {
		t.Fatalf("outcome = %v, want %v\nunwitnessed=%v unrecorded=%v mismatched=%v subtrees=%d unknown=%d reasons=%v",
			v.Outcome, want, v.Unwitnessed, v.Unrecorded, v.Mismatched, len(v.Coverage.UnexplainedSubtrees), len(v.Coverage.Unknown), v.Reasons)
	}
	if v.Faithful != (want == OutcomeFaithful) {
		t.Errorf("Faithful = %v under outcome %v", v.Faithful, v.Outcome)
	}
}

func TestVerify_HonestLevelZero(t *testing.T) {
	g := models.GroundTruth{
		withHash(agentEv(0, models.FileRead, "/etc/hostname"), nil, sp("h1")),
		withHash(agentEv(10, models.FileWrite, "/w/out.txt"), sp("h2"), sp("h3")),
	}
	tr := models.Trajectory{
		withClaimHash(claimAt(0, models.FileRead, "/etc/hostname"), nil, sp("h1")),
		withClaimHash(claimAt(10, models.FileWrite, "/w/out.txt"), sp("h2"), sp("h3")),
	}
	v := run(tr, g)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Corroborated) != 2 || v.Findings() != 0 {
		t.Errorf("corroborated = %d, findings = %d, want 2 and 0", len(v.Corroborated), v.Findings())
	}
}

func withHash(e models.GroundTruthEvent, in, out *string) models.GroundTruthEvent {
	e.InputHash, e.OutputHash = in, out
	return e
}

func withClaimHash(c models.TrajectoryEntry, in, out *string) models.TrajectoryEntry {
	c.InputHash, c.OutputHash = in, out
	return c
}

func TestVerify_EmptyIsFaithfulOnlyWithARoot(t *testing.T) {
	wantOutcome(t, run(nil, nil), OutcomeFaithful)
}

// P1: something observed that no claim explains.
func TestVerify_Omission(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.FileWrite, "/w/a"), agentEv(5, models.FileWrite, "/w/secret")}
	v := run(models.Trajectory{claimAt(0, models.FileWrite, "/w/a")}, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != "/w/secret" {
		t.Errorf("Unrecorded = %v, want /w/secret", v.Unrecorded)
	}
	if v.Advisory {
		t.Error("findings on a complete capture are not advisory")
	}
}

// P2: a claim with nothing behind it.
func TestVerify_Fabrication(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.FileWrite, "/w/a")}
	tr := models.Trajectory{claimAt(0, models.FileWrite, "/w/a"), claimAt(5, models.FileWrite, "/w/ghost")}
	v := run(tr, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != "/w/ghost" {
		t.Errorf("Unwitnessed = %v, want /w/ghost", v.Unwitnessed)
	}
}

// P3: a target substitution is one finding, not a fabrication plus an omission.
func TestVerify_TargetSubstitutionIsOneMismatch(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.FileRead, "/etc/passwd")}
	v := run(models.Trajectory{claimAt(0, models.FileRead, "/etc/hostname")}, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Mismatched) != 1 || len(v.Unwitnessed) != 0 || len(v.Unrecorded) != 0 {
		t.Fatalf("mismatched=%d unwitnessed=%d unrecorded=%d, want 1/0/0", len(v.Mismatched), len(v.Unwitnessed), len(v.Unrecorded))
	}
	if d := v.Mismatched[0].Diffs; len(d) != 1 || d[0] != DiffTarget {
		t.Errorf("Diffs = %v, want [target]", d)
	}
}

func TestVerify_ProcessMasqueradingIsASubstitution(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID), execEv(2, 200, agentPID, "/tmp/evil/cat README"),
		exitEv(3, 200, agentPID, "/tmp/evil/cat README"),
	}
	v := run(claimsFor("/usr/bin/cat README"), g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Mismatched) != 2 {
		t.Errorf("mismatched = %d, want the exec and the exit both substituted", len(v.Mismatched))
	}
}

func TestVerify_HashMismatch(t *testing.T) {
	g := models.GroundTruth{withHash(agentEv(0, models.FileRead, "/w/c"), nil, sp("real"))}
	tr := models.Trajectory{withClaimHash(claimAt(0, models.FileRead, "/w/c"), nil, sp("innocent"))}
	v := run(tr, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Mismatched) != 1 || v.Mismatched[0].Diffs[0] != DiffOutputHash {
		t.Errorf("Mismatched = %+v, want an output_hash difference", v.Mismatched)
	}
}

// The three states of a nil (V-20). Each row pairs one claim with one
// observed event, and says what the content comparison concludes under the
// default (everything expressible), a format that cannot state the field, and a
// format that can.
func TestVerify_ThreeValuedNil(t *testing.T) {
	h := sp("sha256:aa")
	other := sp("sha256:bb")
	type row struct {
		name    string
		claim   models.TrajectoryEntry
		event   models.GroundTruthEvent
		field   string
		cannot  bool // result when the format cannot express the field: mismatch?
		can     bool // result when it can
		deflt   bool // result with a nil Expresses
		comment string
	}
	fc := func(out *string) models.TrajectoryEntry {
		c := claimAt(0, models.FileClose, "/w/f")
		c.OutputHash = out
		return c
	}
	fe := func(out *string) models.GroundTruthEvent {
		e := agentEv(0, models.FileClose, "/w/f")
		e.OutputHash = out
		return e
	}
	wc := func(out *string) models.TrajectoryEntry {
		c := claimAt(0, models.FileWrite, "/w/f")
		c.OutputHash = out
		return c
	}
	we := func(out *string) models.GroundTruthEvent {
		e := agentEv(0, models.FileWrite, "/w/f")
		e.OutputHash = out
		return e
	}
	xc := func(code *int32) models.TrajectoryEntry {
		c := claimAt(0, models.ProcessExit, "/bin/true")
		c.ExitCode = code
		return c
	}
	xe := func(code *int32) models.GroundTruthEvent {
		e := agentEv(0, models.ProcessExit, "/bin/true")
		e.ExitCode = code
		return e
	}
	rc := func(r *string) models.TrajectoryEntry {
		c := claimAt(0, models.NetRequest, "example.com:443/")
		c.RequestHash = r
		return c
	}
	re := func(r *string) models.GroundTruthEvent {
		e := agentEv(0, models.NetRequest, "example.com:443/")
		e.RequestHash = r
		return e
	}
	zero := int32(0)
	one := int32(1)
	rows := []row{
		{"file_close: agent opted out", fc(nil), fe(h), DiffOutputHash, false, true, true, "nil by choice is a finding only if expressible"},
		{"file_close: probe captured nothing", fc(h), fe(nil), DiffOutputHash, false, false, false, "probe gap gets the benefit of the doubt"},
		{"file_close: both nil", fc(nil), fe(nil), DiffOutputHash, false, false, false, ""},
		{"file_close: both set, differ", fc(other), fe(h), DiffOutputHash, true, true, true, "a stated value that differs is always a finding"},
		{"file_write: agent opted out", wc(nil), we(h), DiffOutputHash, false, true, true, "V-28: as on file_close"},
		{"file_write: probe captured nothing", wc(h), we(nil), DiffOutputHash, false, false, false, ""},
		{"file_write: both nil", wc(nil), we(nil), DiffOutputHash, false, false, false, ""},
		{"file_write: both set, differ", wc(other), we(h), DiffOutputHash, true, true, true, ""},
		{"exit: agent opted out", xc(nil), xe(&zero), DiffExitCode, false, true, true, ""},
		{"exit: probe captured nothing", xc(&zero), xe(nil), DiffExitCode, false, false, false, ""},
		{"exit: both set, differ", xc(&zero), xe(&one), DiffExitCode, true, true, true, ""},
		{"request: agent opted out", rc(nil), re(h), DiffRequestHash, false, true, true, ""},
		{"request: probe captured nothing", rc(h), re(nil), DiffRequestHash, false, false, false, ""},
		{"request: both set, differ", rc(other), re(h), DiffRequestHash, true, true, true, ""},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			check := func(label string, ex Expresses, wantMismatch bool) {
				t.Helper()
				v := Verify(Input{
					Claims: models.Trajectory{r.claim}, Ground: models.GroundTruth{r.event},
					RootPID: agentPID, Coverage: completeCov(), Options: Options{Expresses: ex},
				})
				if got := len(v.Mismatched) == 1; got != wantMismatch {
					t.Errorf("%s: mismatched = %v, want %v (%s)", label, got, wantMismatch, r.comment)
				}
				if wantMismatch {
					if d := v.Mismatched[0].Diffs; len(d) == 0 || d[0] != r.field {
						t.Errorf("%s: Diffs = %v, want %s", label, d, r.field)
					}
				}
			}
			check("default", nil, r.deflt)
			check("cannot express", func(models.TrajectoryEntry, string) bool { return false }, r.cannot)
			check("can express", func(models.TrajectoryEntry, string) bool { return true }, r.can)
		})
	}
}

// A claim that states a hash the probe did not capture is not refuted, and it
// is not confirmed either. The pair is corroborated, it is listed as
// unverified, and FAITHFUL is not asserted over it, whatever the format can
// express: an agent that can make the probe drop a hash (a read of the file
// within the settle window does it) would otherwise claim any content (V-22).
func TestVerify_ClaimedContentTheProbeDidNotCaptureIsInconclusive(t *testing.T) {
	h := sp("sha256:aa")
	one := int32(1)
	cases := map[string]struct {
		claim models.TrajectoryEntry
		event models.GroundTruthEvent
		field string
	}{
		"close without an observed hash": {
			withClaimHash(claimAt(0, models.FileClose, "/w/f"), nil, h), agentEv(0, models.FileClose, "/w/f"), DiffOutputHash},
		"write without an observed hash (an adapter's folded replace)": {
			withClaimHash(claimAt(0, models.FileWrite, "/w/f"), nil, h), agentEv(0, models.FileWrite, "/w/f"), DiffOutputHash},
		"exit without an observed code": {
			func() models.TrajectoryEntry {
				c := claimAt(0, models.ProcessExit, "/bin/true")
				c.ExitCode = &one
				return c
			}(),
			agentEv(0, models.ProcessExit, "/bin/true"), DiffExitCode},
		"request without an observed body hash": {
			func() models.TrajectoryEntry {
				c := claimAt(0, models.NetRequest, "example.com:443/")
				c.RequestHash = h
				return c
			}(),
			agentEv(0, models.NetRequest, "example.com:443/"), DiffRequestHash},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			for label, ex := range map[string]Expresses{"default": nil, "cannot express": func(models.TrajectoryEntry, string) bool { return false }} {
				v := Verify(Input{Claims: models.Trajectory{tc.claim}, Ground: models.GroundTruth{tc.event}, RootPID: agentPID, Coverage: completeCov(), Options: Options{Expresses: ex}})
				if v.Outcome != OutcomeInconclusive || v.Findings() != 0 || len(v.Corroborated) != 1 {
					t.Fatalf("%s: outcome = %s findings = %d corroborated = %d, want INCONCLUSIVE with no finding and the pair corroborated", label, v.Outcome, v.Findings(), len(v.Corroborated))
				}
				if len(v.Unverified) != 1 || len(v.Unverified[0].Diffs) != 1 || v.Unverified[0].Diffs[0] != tc.field {
					t.Errorf("%s: Unverified = %+v, want one pair naming %s", label, v.Unverified, tc.field)
				}
				if len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], tc.field) {
					t.Errorf("%s: Reasons = %v", label, v.Reasons)
				}
			}
		})
	}
}

// The gap is about a stated value only. A claim that states nothing, or whose
// field was captured, is not unverified, and a finding elsewhere still makes
// the run NOT FAITHFUL rather than inconclusive.
func TestVerify_UnverifiedIsOnlyAStatedValueTheProbeMissed(t *testing.T) {
	h := sp("sha256:aa")
	both := run(models.Trajectory{withClaimHash(claimAt(0, models.FileClose, "/w/f"), nil, h)}, models.GroundTruth{withHash(agentEv(0, models.FileClose, "/w/f"), nil, h)})
	wantOutcome(t, both, OutcomeFaithful)
	neither := run(models.Trajectory{claimAt(0, models.FileClose, "/w/f")}, models.GroundTruth{agentEv(0, models.FileClose, "/w/f")})
	wantOutcome(t, neither, OutcomeFaithful)
	if len(both.Unverified)+len(neither.Unverified) != 0 {
		t.Error("a captured or an unstated hash was listed as unverified")
	}
	// A stated input hash on an open the probe could not measure is unverified
	// too (V-29): the probe states an input only when it measured it (P-22).
	in := run(models.Trajectory{withClaimHash(claimAt(0, models.FileOpen, "/w/f"), h, nil)}, models.GroundTruth{agentEv(0, models.FileOpen, "/w/f")})
	wantOutcome(t, in, OutcomeInconclusive)
	if len(in.Unverified) != 1 || in.Unverified[0].Diffs[0] != DiffInputHash {
		t.Errorf("Unverified = %+v, want the input_hash", in.Unverified)
	}
	withFinding := run(
		models.Trajectory{withClaimHash(claimAt(0, models.FileClose, "/w/f"), nil, h), claimAt(10, models.FileWrite, "/w/ghost")},
		models.GroundTruth{agentEv(0, models.FileClose, "/w/f")})
	wantOutcome(t, withFinding, OutcomeNotFaithful)
	if len(withFinding.Unverified) != 1 {
		t.Error("the unverified pair must still be reported next to the finding")
	}
}

// V-28: an adapter that claims a write's content on the file_write, as Claude
// Code does for Write and Edit, cannot drop the hash of a tool whose format
// states it. A Write claim with no output_hash against a write the probe
// hashed is a content mismatch; an Edit, whose format may not keep its final
// content, is corroborated. Neither is unverified: that needs a stated value
// the probe missed, the opposite case.
func TestVerify_AWriteThatDropsAHashItsToolStatesIsAMismatch(t *testing.T) {
	h := sp("sha256:aa")
	ex := func(e models.TrajectoryEntry, field string) bool {
		return field != DiffOutputHash || e.Tool == "Write"
	}
	claim := func(tool string) models.TrajectoryEntry {
		c := claimAt(0, models.FileWrite, "/w/f")
		c.Tool = tool
		return c
	}
	g := models.GroundTruth{withHash(agentEv(0, models.FileWrite, "/w/f"), nil, h)}
	verify := func(c models.TrajectoryEntry) Verdict {
		return Verify(Input{Claims: models.Trajectory{c}, Ground: g, RootPID: agentPID, Coverage: completeCov(), Options: Options{Expresses: ex}})
	}

	write := verify(claim("Write"))
	wantOutcome(t, write, OutcomeNotFaithful)
	if len(write.Mismatched) != 1 || len(write.Mismatched[0].Diffs) != 1 || write.Mismatched[0].Diffs[0] != DiffOutputHash {
		t.Errorf("Write: Mismatched = %+v, want one pair differing on output_hash", write.Mismatched)
	}
	if len(write.Unwitnessed)+len(write.Unrecorded)+len(write.Unverified) != 0 {
		t.Errorf("Write: unwitnessed = %v unrecorded = %v unverified = %v, want only the mismatch", write.Unwitnessed, write.Unrecorded, write.Unverified)
	}

	edit := verify(claim("Edit"))
	wantOutcome(t, edit, OutcomeFaithful)
	if len(edit.Corroborated) != 1 || len(edit.Unverified) != 0 {
		t.Errorf("Edit: corroborated = %d unverified = %+v, want the pair corroborated and nothing unverified", len(edit.Corroborated), edit.Unverified)
	}
}

// Expresses is asked per entry and per field, so one agent can state a field
// for one tool and not for another (Claude Code's Edit versus Write).
func TestVerify_ExpressesIsPerEntry(t *testing.T) {
	h := sp("sha256:aa")
	edit := claimAt(0, models.FileClose, "/w/edited")
	write := claimAt(1, models.FileClose, "/w/written")
	g := models.GroundTruth{
		withHash(agentEv(0, models.FileClose, "/w/edited"), nil, h),
		withHash(agentEv(1, models.FileClose, "/w/written"), nil, h),
	}
	ex := func(e models.TrajectoryEntry, field string) bool { return e.Target == "/w/written" }
	v := Verify(Input{Claims: models.Trajectory{edit, write}, Ground: g, RootPID: agentPID, Coverage: completeCov(), Options: Options{Expresses: ex}})
	if len(v.Mismatched) != 1 || v.Mismatched[0].Entry.Target != "/w/written" {
		t.Errorf("Mismatched = %+v, want only the entry whose format could state the hash", v.Mismatched)
	}
	if len(v.Corroborated) != 1 || v.Corroborated[0].Entry.Target != "/w/edited" {
		t.Errorf("Corroborated = %+v, want the entry whose format cannot state it", v.Corroborated)
	}
}

// InputHash has no round-trip support yet, so an omitted input hash agrees
// under every declaration.
func TestVerify_OmittedInputHashStaysPermissive(t *testing.T) {
	g := models.GroundTruth{withHash(agentEv(0, models.FileRead, "/w/c"), sp("in"), nil)}
	v := run(models.Trajectory{claimAt(0, models.FileRead, "/w/c")}, g)
	wantOutcome(t, v, OutcomeFaithful)
}

// What a build does is explained by the command the agent claimed. None of the
// descendants' events is compared against anything or reads as an omission.
func TestVerify_SubtreeEventsAreNotOmissions(t *testing.T) {
	v := run(claimsFor("/bin/sh -c build", "/usr/bin/curl http://x"), twoCommandTruth())
	wantOutcome(t, v, OutcomeFaithful)
	if v.Coverage.Explained == 0 {
		t.Error("Coverage.Explained = 0, want the subtree events counted")
	}
}

// A command nothing claims is an omission and cannot hide by being a command.
func TestVerify_UnclaimedCommand(t *testing.T) {
	v := run(claimsFor("/bin/sh -c build"), twoCommandTruth())
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Coverage.UnexplainedSubtrees) != 1 {
		t.Fatalf("UnexplainedSubtrees = %d, want the curl subtree", len(v.Coverage.UnexplainedSubtrees))
	}
	if got := v.Coverage.UnexplainedSubtrees[0].Process.PID; got != 300 {
		t.Errorf("unexplained subtree pid = %d, want 300", got)
	}
}

// A subshell that forks and never execs has no exec record. Nothing the agent
// said accounts for it, and it must not escape by having no exec.
func TestVerify_ForkWithoutExecIsAnUnexplainedSubtree(t *testing.T) {
	g := models.GroundTruth{fork(1, 400, agentPID), fsEv(2, 400, "/w/from-subshell")}
	v := run(nil, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Coverage.UnexplainedSubtrees) != 1 {
		t.Errorf("UnexplainedSubtrees = %d, want 1", len(v.Coverage.UnexplainedSubtrees))
	}
}

// Level 2 and below are never claimed, so their events do not move the
// verdict whether or not the file name looks like anything in the trajectory.
func TestVerify_DescendantEventsDoNotCorroborateClaims(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID), execEv(2, 200, agentPID, "/bin/sh -c x"),
		fsEv(3, 200, "/w/a"),
		exitEv(4, 200, agentPID, "/bin/sh -c x"),
	}
	tr := append(claimsFor("/bin/sh -c x"), claimAt(3, models.FileWrite, "/w/a"))
	v := run(tr, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != "/w/a" {
		t.Errorf("Unwitnessed = %v, want the claim of a subtree write (D3)", v.Unwitnessed)
	}
}

// An event by a process the tree cannot place is reported, never a finding.
// A read stays informational; a write-class event under the workspace means
// the workspace changed under something the capture could not attribute, so
// FAITHFUL is not asserted over it (V-25).
func TestVerify_OutsideEventsAreReportedAndDoNotBlock(t *testing.T) {
	claims := models.Trajectory{claimAt(0, models.FileWrite, "/w/a")}
	read := models.GroundTruthEvent{Timestamp: at(1), ActionType: models.FileOpen, Target: "/w/stranger", PID: 7777}
	v := run(claims, models.GroundTruth{agentEv(0, models.FileWrite, "/w/a"), read})
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Coverage.Outside) != 1 || len(v.OutsideWrites) != 0 {
		t.Errorf("Outside = %d, OutsideWrites = %d, want 1 reported and none a write", len(v.Coverage.Outside), len(v.OutsideWrites))
	}

	v = run(claims, models.GroundTruth{agentEv(0, models.FileWrite, "/w/a"), fsEv(1, 7777, "/w/stranger")})
	wantOutcome(t, v, OutcomeInconclusive)
	if v.Findings() != 0 || len(v.OutsideWrites) != 1 || len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "cannot place") {
		t.Errorf("findings=%d outsideWrites=%v reasons=%v", v.Findings(), v.OutsideWrites, v.Reasons)
	}

	// Outside the workspace it is informational: the capture keeps such
	// events only under the workspace, so a known workspace bounds them.
	g := models.GroundTruth{agentEv(0, models.FileWrite, "/w/a"), fsEv(1, 7777, "/elsewhere/x")}
	v = Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Workspace: "/w"})
	wantOutcome(t, v, OutcomeFaithful)

	// Next to a finding the run is NOT FAITHFUL and the writes are still listed.
	v = run(claims, models.GroundTruth{agentEv(0, models.FileWrite, "/w/a"), fsEv(1, 7777, "/w/stranger"), agentEv(2, models.FileWrite, "/w/hidden")})
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.OutsideWrites) != 1 {
		t.Errorf("OutsideWrites = %v", v.OutsideWrites)
	}
}

func TestVerify_BaselineExplainsHarnessActivity(t *testing.T) {
	g := models.GroundTruth{
		agentEv(0, models.FileRead, "/home/u/.config/agent/settings"),
		fork(1, 200, agentPID), execEv(2, 200, agentPID, "/usr/bin/git config"),
		exitEv(3, 200, agentPID, "/usr/bin/git config"),
		agentEv(10, models.FileWrite, "/w/a"),
	}
	tr := models.Trajectory{claimAt(10, models.FileWrite, "/w/a")}
	base := func(e models.GroundTruthEvent) bool {
		return strings.Contains(e.Target, "/.config/agent/") || strings.HasPrefix(e.Target, "/usr/bin/git config")
	}
	wantOutcome(t, Verify(Input{Claims: tr, Ground: g, RootPID: agentPID, Coverage: completeCov()}), OutcomeNotFaithful)
	v := Verify(Input{Claims: tr, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: base})
	wantOutcome(t, v, OutcomeFaithful)
}

// A baseline must not be a place to hide: an event it does not recognise is
// still an omission.
func TestVerify_BaselineDoesNotSubtractWhatItDoesNotRecognise(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.FileWrite, "/w/exfil")}
	v := Verify(Input{Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: func(models.GroundTruthEvent) bool { return false }})
	wantOutcome(t, v, OutcomeNotFaithful)
}

// A format with no exit information has no claim for an observed exit.
func TestVerify_IgnoreExits(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID), execEv(2, 200, agentPID, "/bin/ls"), exitEv(3, 200, agentPID, "/bin/ls"),
	}
	tr := models.Trajectory{claimAt(2, models.ProcessExec, "/bin/ls")}
	wantOutcome(t, run(tr, g), OutcomeNotFaithful) // the exit is unclaimed by default
	v := Verify(Input{Claims: tr, Ground: g, RootPID: agentPID, Coverage: completeCov(), Options: Options{IgnoreExits: true}})
	wantOutcome(t, v, OutcomeFaithful)
	// The exec is still required: ignoring exits must not ignore the command.
	v = Verify(Input{Ground: g, RootPID: agentPID, Coverage: completeCov(), Options: Options{IgnoreExits: true}})
	wantOutcome(t, v, OutcomeNotFaithful)
}

// V6: a claim interval comes from the adversary. An observed action outside
// it is reported against the claim, and the pair stays paired.
func TestVerify_OutsideInterval(t *testing.T) {
	g := models.GroundTruth{agentEv(5000, models.FileWrite, "/w/a")}
	c := claimAt(0, models.FileWrite, "/w/a")
	end := at(100)
	c.End = &end
	v := run(models.Trajectory{c}, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Corroborated) != 1 || len(v.OutsideInterval) != 1 {
		t.Errorf("corroborated=%d outside=%d, want the pair kept and flagged", len(v.Corroborated), len(v.OutsideInterval))
	}
	v = Verify(Input{Claims: models.Trajectory{c}, Ground: g, RootPID: agentPID, Coverage: completeCov(), Options: Options{IntervalSlack: 10 * time.Second}})
	wantOutcome(t, v, OutcomeFaithful)
}

// V6: time orders events and does not pair them. A constant offset between
// the trajectory's clock and the kernel's changes nothing.
func TestVerify_ClockOffsetDoesNotChangeTheVerdict(t *testing.T) {
	g := models.GroundTruth{
		agentEv(0, models.FileWrite, "/w/a"), agentEv(10, models.FileWrite, "/w/b"), agentEv(20, models.FileWrite, "/w/c"),
	}
	tr := models.Trajectory{
		claimAt(0, models.FileWrite, "/w/a"), claimAt(10, models.FileWrite, "/w/b"), claimAt(20, models.FileWrite, "/w/c"),
	}
	for i := range tr {
		tr[i].Timestamp = tr[i].Timestamp.Add(3 * time.Hour)
	}
	wantOutcome(t, run(tr, g), OutcomeFaithful)
}

// Repeated actions on one target pair in order, each by content.
func TestVerify_RepeatedActionsPairByPosition(t *testing.T) {
	g := models.GroundTruth{
		withHash(agentEv(0, models.FileWrite, "/w/log"), nil, sp("h1")),
		withHash(agentEv(1, models.FileWrite, "/w/log"), nil, sp("h2")),
	}
	tr := models.Trajectory{
		withClaimHash(claimAt(0, models.FileWrite, "/w/log"), nil, sp("h1")),
		withClaimHash(claimAt(1, models.FileWrite, "/w/log"), nil, sp("h2")),
	}
	wantOutcome(t, run(tr, g), OutcomeFaithful)
	tr[1].OutputHash = sp("h3")
	v := run(tr, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Mismatched) != 1 || v.Mismatched[0].Event.OutputHash == nil || *v.Mismatched[0].Event.OutputHash != "h2" {
		t.Errorf("Mismatched = %+v, want the second write", v.Mismatched)
	}
}

// Directory-covers-file leniency applies only to a record the probe could not
// resolve. An exact event equal to the parent directory launders nothing.
func TestVerify_DirectoryFallbackRequiresAmbiguousFlag(t *testing.T) {
	c := claimAt(0, models.FileWrite, "/workspace/secret.txt")
	exact := models.GroundTruthEvent{Timestamp: at(0), ActionType: models.FileWrite, Target: "/workspace", PID: agentPID}
	v := run(models.Trajectory{c}, models.GroundTruth{exact})
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Corroborated) != 0 {
		t.Errorf("exact directory event corroborated a file claim: %+v", v.Corroborated)
	}

	amb := exact
	amb.PathIsAmbiguous = true
	v = run(models.Trajectory{c}, models.GroundTruth{amb})
	wantOutcome(t, v, OutcomeFaithful)
}

// One ambiguous directory event explains one file claim, not every file in the
// directory, and the verdict says the choice of which was arbitrary.
func TestVerify_AmbiguousDirectoryEventExplainsOneClaim(t *testing.T) {
	amb := models.GroundTruthEvent{Timestamp: at(0), ActionType: models.FileWrite, Target: "/workspace", PID: agentPID, PathIsAmbiguous: true}
	tr := models.Trajectory{claimAt(0, models.FileWrite, "/workspace/a.txt"), claimAt(1, models.FileWrite, "/workspace/b.txt")}
	v := run(tr, models.GroundTruth{amb})
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Corroborated) != 1 || len(v.Unwitnessed) != 1 {
		t.Errorf("corroborated=%d unwitnessed=%d, want 1 and 1", len(v.Corroborated), len(v.Unwitnessed))
	}
	if !v.Ambiguous {
		t.Error("Ambiguous = false: either claim could have been the unwitnessed one")
	}
}

// Listeners are capability evidence: observed and counted, never aligned.
func TestVerify_ListenersAreCapabilityNotUnrecorded(t *testing.T) {
	g := models.GroundTruth{
		agentEv(0, models.NetBind, "0.0.0.0:8080"),
		agentEv(1, models.NetListen, "0.0.0.0:8080"),
		agentEv(2, models.NetUnixConnect, "unix:/var/run/docker.sock"),
		agentEv(3, models.ProcessExec, "ls"),
	}
	v := run(models.Trajectory{claimAt(3, models.ProcessExec, "ls")}, g)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Capability) != 3 || len(v.Unrecorded) != 0 || len(v.Corroborated) != 1 {
		t.Errorf("capability=%d unrecorded=%d corroborated=%d, want 3/0/1", len(v.Capability), len(v.Unrecorded), len(v.Corroborated))
	}
}

// A hand-built claim of an unclaimable type must not launder a listener into a
// corroborated action.
func TestVerify_ListenerClaimNeverCorroborates(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.NetListen, "0.0.0.0:8080")}
	v := run(models.Trajectory{claimAt(0, models.NetListen, "0.0.0.0:8080")}, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Corroborated) != 0 || len(v.Unwitnessed) != 1 {
		t.Errorf("corroborated=%d unwitnessed=%d, want 0 and 1", len(v.Corroborated), len(v.Unwitnessed))
	}
}

func TestVerify_ForkRecordsAreNeitherUnrecordedNorCapability(t *testing.T) {
	g := models.GroundTruth{fork(1, 101, agentPID), fork(2, 102, 101), agentEv(3, models.NetListen, "0.0.0.0:80")}
	v := run(nil, g)
	// The two forks are a command with no claim, which is a finding of its
	// own. They must not also appear as unrecorded actions or capability.
	if len(v.Unrecorded) != 0 {
		t.Errorf("fork records became Unrecorded: %v", v.Unrecorded)
	}
	if len(v.Capability) != 1 || v.Capability[0].ActionType != models.NetListen {
		t.Errorf("Capability = %v, want only the listener", v.Capability)
	}
}

// --- Outcome rules (V-13 to V-15) ---

func TestVerify_NoRootPIDIsInconclusive(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.FileWrite, "/w/a")}
	v := Verify(Input{Claims: models.Trajectory{claimAt(0, models.FileWrite, "/w/a")}, Ground: g, Coverage: completeCov()})
	wantOutcome(t, v, OutcomeInconclusive)
	if len(v.Reasons) == 0 || !strings.Contains(v.Reasons[0], "root pid") {
		t.Errorf("Reasons = %v, want the missing root named", v.Reasons)
	}
	if len(v.Alignments) != 0 || v.Findings() != 0 {
		t.Error("a run with no root must not report findings from an alignment it could not attribute")
	}
}

func TestVerify_LegacyGroundTruthWithoutPIDsIsInconclusive(t *testing.T) {
	g := models.GroundTruth{{Timestamp: at(0), ActionType: models.FileWrite, Target: "/w/a"}}
	v := Verify(Input{Claims: models.Trajectory{claimAt(0, models.FileWrite, "/w/a")}, Ground: g, RootPID: agentPID, Coverage: completeCov()})
	wantOutcome(t, v, OutcomeInconclusive)
	if len(v.Reasons) == 0 || !strings.Contains(v.Reasons[0], "pid") || v.Findings() != 0 {
		t.Errorf("Reasons = %v findings = %d, want the missing pids named and no findings", v.Reasons, v.Findings())
	}
}

func TestVerify_UnknownEventsWithAFindingAreAdvisory(t *testing.T) {
	g := models.GroundTruth{
		agentEv(0, models.FileWrite, "/w/a"),
		{Timestamp: at(1), ActionType: models.FileWrite, Target: "/w/nopid"},
	}
	v := run(models.Trajectory{claimAt(0, models.FileWrite, "/w/a"), claimAt(1, models.FileWrite, "/w/ghost")}, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if !v.Advisory {
		t.Error("Advisory = false: an unplaced event can manufacture a fabrication finding")
	}
}

func TestVerify_NilCoverageIsInconclusive(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.FileWrite, "/w/a")}
	v := Verify(Input{Claims: models.Trajectory{claimAt(0, models.FileWrite, "/w/a")}, Ground: g, RootPID: agentPID})
	wantOutcome(t, v, OutcomeInconclusive)
}

// Any loss counter above zero makes FAITHFUL unavailable, however clean the
// alignment is.
func TestVerify_LossIsInconclusive(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.FileWrite, "/w/a")}
	tr := models.Trajectory{claimAt(0, models.FileWrite, "/w/a")}
	losses := map[string]models.ProbeCoverage{
		"ringbuf drops":      {Ran: true, RingbufDrops: 1},
		"untracked children": {Ran: true, UntrackedChildren: 1},
		"state map full":     {Ran: true, StateMapFull: 1},
		"channel drops":      {Ran: true, ChannelDrops: 1},
		"queue overflow":     {Ran: true, QueueOverflow: true},
	}
	for name, p := range losses {
		t.Run(name, func(t *testing.T) {
			c := cov(map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": p})
			v := Verify(Input{Claims: tr, Ground: g, RootPID: agentPID, Coverage: c})
			wantOutcome(t, v, OutcomeInconclusive)
			if v.Outcome.ExitCode() != 2 {
				t.Errorf("exit code = %d, want 2", v.Outcome.ExitCode())
			}
			if len(v.Reasons) == 0 {
				t.Error("no reason given for INCONCLUSIVE")
			}
		})
	}
}

// Content gaps are notes, not loss: they limit what content checks can say but
// do not make the event set incomplete.
func TestVerify_ContentNotesAreNotLoss(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.FileWrite, "/w/a")}
	c := cov(map[string]models.ProbeCoverage{"fs": {Ran: true}, "net": {Ran: true, FaultedReads: 3, Content: models.ContentAttachFailed}})
	v := Verify(Input{Claims: models.Trajectory{claimAt(0, models.FileWrite, "/w/a")}, Ground: g, RootPID: agentPID, Coverage: c})
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Completeness.Notes) != 2 {
		t.Errorf("Notes = %v, want both content gaps noted", v.Completeness.Notes)
	}
}

// Loss does not hide a finding: it stays NOT FAITHFUL, marked advisory.
func TestVerify_FindingsUnderLossAreAdvisory(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.FileWrite, "/w/secret")}
	c := cov(map[string]models.ProbeCoverage{"fs": {Ran: true, RingbufDrops: 4}})
	v := Verify(Input{Ground: g, RootPID: agentPID, Coverage: c})
	wantOutcome(t, v, OutcomeNotFaithful)
	if !v.Advisory || len(v.Reasons) == 0 {
		t.Errorf("Advisory = %v, Reasons = %v, want advisory with the loss named", v.Advisory, v.Reasons)
	}
}

func TestOutcomeExitCodes(t *testing.T) {
	for o, want := range map[Outcome]int{OutcomeFaithful: 0, OutcomeNotFaithful: 1, OutcomeInconclusive: 2} {
		if o.ExitCode() != want {
			t.Errorf("%v.ExitCode() = %d, want %d", o, o.ExitCode(), want)
		}
	}
}

func TestVerify_TooLargeToAlignIsInconclusive(t *testing.T) {
	// Every claim disagrees with every event, so the band (V-42) is the
	// whole table, and n*n exceeds the alignment budget, lowered here.
	lowerMaxCells(t, 1<<16)
	const n = 400
	var g models.GroundTruth
	var tr models.Trajectory
	for i := 0; i < n; i++ {
		g = append(g, agentEv(i, models.FileWrite, fmt.Sprintf("/w/e%d", i)))
		tr = append(tr, claimAt(i, models.FileWrite, fmt.Sprintf("/w/c%d", i)))
	}
	v := run(tr, g)
	wantOutcome(t, v, OutcomeInconclusive)
}

// An event with no pid among placed ones cannot be shown to be explained, so a
// run with no findings still cannot be FAITHFUL.
func TestVerify_UnplacedEventBlocksFaithful(t *testing.T) {
	g := models.GroundTruth{
		agentEv(0, models.FileWrite, "/w/a"),
		{Timestamp: at(1), ActionType: models.FileWrite, Target: "/w/nopid"},
	}
	v := run(models.Trajectory{claimAt(0, models.FileWrite, "/w/a")}, g)
	wantOutcome(t, v, OutcomeInconclusive)
	if len(v.Coverage.Unknown) != 1 {
		t.Errorf("Unknown = %d, want 1", len(v.Coverage.Unknown))
	}
}

// A process that forks and never does anything observable has nothing to
// explain. Go's os/exec forks one such child per process to probe for pidfd
// support, so an honest Go agent has one. It is reported as quiet, and it is
// not a finding.
func TestVerify_QuietForkIsNotAFinding(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 400, agentPID), // probes pidfd support and exits
		agentEv(2, models.FileWrite, "/w/a"),
	}
	v := run(models.Trajectory{claimAt(2, models.FileWrite, "/w/a")}, g)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Coverage.Quiet) != 1 || len(v.Coverage.UnexplainedSubtrees) != 0 {
		t.Errorf("quiet = %d, unexplained subtrees = %d, want 1 and 0", len(v.Coverage.Quiet), len(v.Coverage.UnexplainedSubtrees))
	}
}

// Quiet is decided by what the subtree did, not by the first process alone: a
// fork that never execs but whose descendant runs a command is not quiet.
func TestVerify_ForkWhoseDescendantActsIsNotQuiet(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 400, agentPID),
		fork(2, 401, 400), execEv(3, 401, 400, "/usr/bin/curl http://x"),
	}
	v := run(nil, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Coverage.Quiet) != 0 || len(v.Coverage.UnexplainedSubtrees) != 1 {
		t.Errorf("quiet = %d, unexplained subtrees = %d, want 0 and 1", len(v.Coverage.Quiet), len(v.Coverage.UnexplainedSubtrees))
	}
}

// A quiet process is not a hiding place for a later action: the moment it
// writes, the write is an event with no claim to explain it.
func TestVerify_QuietForkThatLaterActsIsNotQuiet(t *testing.T) {
	g := models.GroundTruth{fork(1, 400, agentPID), fsEv(900, 400, "/w/late")}
	v := run(nil, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Coverage.Quiet) != 0 {
		t.Error("a fork that wrote a file was reported as quiet")
	}
}

// A file claim the capture could not have witnessed is set aside, not aligned:
// it is neither a fabrication nor confirmed, and FAITHFUL is not asserted over
// it. Which claims those are comes from the capture's fs_scope record, or from
// the workspace alone for a capture that predates the record (V-23).
func TestVerify_FileClaimsOutsideTheCaptureScopeAreSetAside(t *testing.T) {
	claimOut := claimAt(0, models.FileWrite, "/home/u/.bashrc")
	claimIn := claimAt(10, models.FileWrite, "/ws/a.txt")
	eventIn := agentEv(10, models.FileWrite, "/ws/a.txt")
	verify := func(scope *models.FSScope, workspace string, claims ...models.TrajectoryEntry) Verdict {
		return Verify(Input{Claims: claims, Ground: models.GroundTruth{eventIn}, RootPID: agentPID, Coverage: completeCov(), FSScope: scope, Workspace: workspace})
	}
	t.Run("legacy capture: outside the workspace is out of scope", func(t *testing.T) {
		v := verify(nil, "/ws", claimOut, claimIn)
		wantOutcome(t, v, OutcomeInconclusive)
		if len(v.OutOfScope) != 1 || v.OutOfScope[0].Target != "/home/u/.bashrc" || len(v.Corroborated) != 1 || v.Findings() != 0 {
			t.Errorf("outOfScope=%v corroborated=%d findings=%d", v.OutOfScope, len(v.Corroborated), v.Findings())
		}
		if len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "fs_scope") {
			t.Errorf("reasons = %v", v.Reasons)
		}
	})
	t.Run("legacy capture, a look-alike prefix is outside", func(t *testing.T) {
		v := verify(nil, "/ws", claimAt(0, models.FileWrite, "/ws2/x"), claimIn)
		if len(v.OutOfScope) != 1 {
			t.Errorf("/ws2 was read as inside /ws: %v", v.OutOfScope)
		}
	})
	t.Run("no record and no workspace: everything is in scope", func(t *testing.T) {
		v := verify(nil, "", claimOut, claimIn)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.OutOfScope) != 0 || len(v.Unwitnessed) != 1 {
			t.Errorf("outOfScope=%v unwitnessed=%v", v.OutOfScope, v.Unwitnessed)
		}
	})
	t.Run("tree-or-workspace with / marked: the home write is in scope and unwitnessed", func(t *testing.T) {
		scope := &models.FSScope{Rule: models.FSScopeTreeOrWorkspace, Mounts: []string{"/", "/tmp"}}
		v := verify(scope, "/ws", claimOut, claimIn)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.OutOfScope) != 0 || len(v.Unwitnessed) != 1 {
			t.Errorf("outOfScope=%v unwitnessed=%v", v.OutOfScope, v.Unwitnessed)
		}
	})
	t.Run("a path under an unmarked mount is out of scope, under a marked one in", func(t *testing.T) {
		scope := &models.FSScope{Rule: models.FSScopeTreeOrWorkspace, Mounts: []string{"/", "/tmp"}, Unmarked: map[string]string{"/var/lib/docker/x/merged": "operation not supported"}}
		v := verify(scope, "/ws", claimAt(0, models.FileWrite, "/var/lib/docker/x/merged/etc/passwd"), claimAt(1, models.FileOpen, "/var/lib/docker/x/other"), claimIn)
		wantOutcome(t, v, OutcomeNotFaithful) // the /var/lib/docker/x/other open is in scope and unwitnessed
		if len(v.OutOfScope) != 1 || v.OutOfScope[0].Target != "/var/lib/docker/x/merged/etc/passwd" {
			t.Errorf("outOfScope = %v", v.OutOfScope)
		}
	})
	t.Run("other lanes have no path scope", func(t *testing.T) {
		v := verify(nil, "/ws", claimAt(0, models.ProcessExec, "/usr/bin/true"), claimIn)
		if len(v.OutOfScope) != 0 || len(v.Unwitnessed) != 1 {
			t.Errorf("a process claim was scoped by path: outOfScope=%v", v.OutOfScope)
		}
	})
	t.Run("set aside next to a finding", func(t *testing.T) {
		v := verify(nil, "/ws", claimOut, claimIn, claimAt(20, models.FileWrite, "/ws/ghost"))
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.OutOfScope) != 1 || len(v.Unwitnessed) != 1 {
			t.Errorf("outOfScope=%v unwitnessed=%v", v.OutOfScope, v.Unwitnessed)
		}
	})
}

// Every level-1 subtree reaches the verdict with its exec, its content and
// its listeners, whatever the verdict made of it, so a reader can see what a
// command did (D3: reported, never aligned).
func TestVerify_CommandsCarryTheirSubtrees(t *testing.T) {
	g := models.GroundTruth{
		{Timestamp: at(0), ActionType: models.ProcessFork, Target: "200", PID: 200, PPID: agentPID},
		{Timestamp: at(1), ActionType: models.ProcessExec, Target: "/bin/sh -c x", PID: 200, PPID: agentPID},
		{Timestamp: at(2), ActionType: models.FileWrite, Target: "/w/out", PID: 200},
		{Timestamp: at(3), ActionType: models.NetListen, Target: "127.0.0.1:9000", PID: 200},
	}
	v := run(models.Trajectory{claimAt(1, models.ProcessExec, "/bin/sh -c x")}, g)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Commands) != 1 || v.Commands[0].Exec == nil || len(v.Commands[0].Content) != 1 || len(v.Commands[0].Capability) != 1 {
		t.Fatalf("Commands = %+v", v.Commands)
	}
	if v.Commands[0].Capability[0].Target != "127.0.0.1:9000" || len(v.Capability) != 1 {
		t.Error("the listener is missing from the command or from the verdict's capability list")
	}
}

// An unexplained level-0 file event under the harness's own directories is
// unexplained harness activity: not a finding, and not FAITHFUL either. A
// file event elsewhere and a command stay findings whatever their path, and
// an adapter that declares nothing changes nothing (V-24).
func TestVerify_UnexplainedHarnessActivityIsInconclusive(t *testing.T) {
	owned := func(p string) bool { return strings.HasPrefix(p, "/home/u/.claude/") }
	claim := claimAt(0, models.FileWrite, "/w/a")
	event := agentEv(0, models.FileWrite, "/w/a")
	backup := agentEv(1, models.FileWrite, "/home/u/.claude/backups/x")
	verify := func(owned func(string) bool, g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: models.Trajectory{claim}, Ground: g, RootPID: agentPID, Coverage: completeCov(), Options: Options{HarnessOwned: owned}})
	}
	t.Run("declared directory: inconclusive, no finding", func(t *testing.T) {
		v := verify(owned, event, backup)
		wantOutcome(t, v, OutcomeInconclusive)
		if v.Findings() != 0 || len(v.Unrecorded) != 0 || len(v.UnexplainedHarness) != 1 || len(v.Coverage.UnexplainedActions) != 0 {
			t.Errorf("findings=%d unrecorded=%v harness=%v coverage=%v", v.Findings(), v.Unrecorded, v.UnexplainedHarness, v.Coverage.UnexplainedActions)
		}
		if len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "harness") {
			t.Errorf("reasons = %v", v.Reasons)
		}
	})
	t.Run("nothing declared: a finding as before", func(t *testing.T) {
		v := verify(nil, event, backup)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || len(v.UnexplainedHarness) != 0 {
			t.Errorf("unrecorded=%v harness=%v", v.Unrecorded, v.UnexplainedHarness)
		}
	})
	t.Run("elsewhere: a finding", func(t *testing.T) {
		v := verify(owned, event, agentEv(1, models.FileWrite, "/home/u/.ssh/authorized_keys"))
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || len(v.UnexplainedHarness) != 0 {
			t.Errorf("unrecorded=%v harness=%v", v.Unrecorded, v.UnexplainedHarness)
		}
	})
	t.Run("a command under the directory stays a finding", func(t *testing.T) {
		g := models.GroundTruth{event,
			{Timestamp: at(1), ActionType: models.ProcessFork, Target: "200", PID: 200, PPID: agentPID},
			{Timestamp: at(2), ActionType: models.ProcessExec, Target: "/home/u/.claude/hook.sh", PID: 200, PPID: agentPID},
			{Timestamp: at(3), ActionType: models.NetConnect, Target: "evil.example", PID: 200},
		}
		v := verify(owned, g...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Coverage.UnexplainedSubtrees) != 1 || len(v.UnexplainedHarness) != 0 {
			t.Errorf("subtrees=%d harness=%v", len(v.Coverage.UnexplainedSubtrees), v.UnexplainedHarness)
		}
	})
	t.Run("reported next to a finding", func(t *testing.T) {
		v := verify(owned, event, backup, agentEv(2, models.FileWrite, "/w/ghost"))
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.UnexplainedHarness) != 1 || len(v.Unrecorded) != 1 {
			t.Errorf("unrecorded=%v harness=%v", v.Unrecorded, v.UnexplainedHarness)
		}
	})
}

// A truncated observed command line pairs with a claim it is a prefix of, as
// a corroborated pair unverified on its target, so the run is INCONCLUSIVE and
// not a false substitution. A claim it is not a prefix of is a mismatch, and
// an untruncated prefix is a mismatch as before (P-19, V-26).
func TestVerify_TruncatedCommandLinePairsByPrefix(t *testing.T) {
	long := "/bin/sh -c " + strings.Repeat("echo x; ", 2000)
	cut := func(truncated bool) models.GroundTruthEvent {
		e := agentEv(0, models.ProcessExec, long[:100])
		e.TargetTruncated = truncated
		return e
	}
	v := run(models.Trajectory{claimAt(0, models.ProcessExec, long)}, models.GroundTruth{cut(true)})
	wantOutcome(t, v, OutcomeInconclusive)
	if len(v.Corroborated) != 1 || len(v.Unverified) != 1 || v.Unverified[0].Diffs[0] != DiffTarget || v.Findings() != 0 {
		t.Errorf("corroborated=%d unverified=%v findings=%d", len(v.Corroborated), v.Unverified, v.Findings())
	}
	v = run(models.Trajectory{claimAt(0, models.ProcessExec, "/bin/sh -c something else")}, models.GroundTruth{cut(true)})
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Mismatched) != 1 {
		t.Errorf("a truncated line that is not a prefix must mismatch: %+v", v)
	}
	v = run(models.Trajectory{claimAt(0, models.ProcessExec, long)}, models.GroundTruth{cut(false)})
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Mismatched) != 1 {
		t.Errorf("an untruncated prefix is a different command: %+v", v)
	}
}

// Harness-owned events no claim names leave the aligned sequence before
// alignment: left in, a fabricated claim next to them could be read as a
// substitution with a real claim pushed onto the harness event at the same
// cost (seen on the edits capture: a fabrication classified as a substitution
// in two runs of a hundred). An event on a path a claim does name stays, so an
// honest write into the harness's directory pairs.
func TestVerify_HarnessOwnedEventsDoNotAbsorbClaims(t *testing.T) {
	owned := func(p string) bool { return strings.HasPrefix(p, "/home/u/.claude/") }
	h := sp("sha256:aa")
	g := models.GroundTruth{
		withHash(agentEv(0, models.FileWrite, "/home/u/.claude/policy-limits.json"), nil, nil),
		withHash(agentEv(1, models.FileClose, "/home/u/.claude/policy-limits.json"), nil, h),
		withHash(agentEv(2, models.FileWrite, "/w/notes.txt"), nil, h),
	}
	claims := models.Trajectory{
		withClaimHash(claimAt(0, models.FileWrite, "/w/report.md"), nil, sp("sha256:fake")), // fabricated
		withClaimHash(claimAt(2, models.FileWrite, "/w/notes.txt"), nil, h),
	}
	v := Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Options: Options{HarnessOwned: owned}})
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != "/w/report.md" || len(v.Mismatched) != 0 || len(v.Corroborated) != 1 || len(v.UnexplainedHarness) != 2 || v.Ambiguous {
		t.Errorf("unwitnessed=%v mismatched=%v corroborated=%d harness=%d ambiguous=%v", v.Unwitnessed, v.Mismatched, len(v.Corroborated), len(v.UnexplainedHarness), v.Ambiguous)
	}

	// A claim that names the harness path pairs with the event there.
	claims = models.Trajectory{withClaimHash(claimAt(0, models.FileWrite, "/home/u/.claude/policy-limits.json"), nil, nil)}
	v = Verify(Input{Claims: claims, Ground: g[:1], RootPID: agentPID, Coverage: completeCov(), Options: Options{HarnessOwned: owned}})
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Corroborated) != 1 || len(v.UnexplainedHarness) != 0 {
		t.Errorf("corroborated=%d harness=%d", len(v.Corroborated), len(v.UnexplainedHarness))
	}
}

// V-30: a level-0 event the baseline recognises stays in the sequence when an
// in-scope claim names its path. Every control's Bash opens its own background
// output file, so the baseline holds the open, and an honest Read of that file
// must pair with it instead of losing it to the subtraction. One left unpaired
// is explained by the baseline, as if subtracted: never Unrecorded, never
// unexplained harness activity.
func TestVerify_BaselineEventsOnAClaimedPathPairWithTheClaim(t *testing.T) {
	const out = "/tmp/claude-1000/w/SESSION/tasks/N.output"
	owned := func(p string) bool { return strings.HasPrefix(p, "/tmp/claude-1000/") }
	base := func(e models.GroundTruthEvent) bool { return e.Target == out }
	h := sp("sha256:bb")
	verify := func(claims models.Trajectory, g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: base, Options: Options{HarnessOwned: owned}})
	}

	t.Run("an honest Read of a baselined path is corroborated", func(t *testing.T) {
		v := verify(models.Trajectory{claimAt(5, models.FileOpen, out)}, agentEv(5, models.FileOpen, out))
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.Corroborated) != 1 || len(v.Unwitnessed) != 0 {
			t.Errorf("corroborated=%d unwitnessed=%v", len(v.Corroborated), v.Unwitnessed)
		}
	})
	t.Run("the harness's own events on the path stay unpaired and are baselined", func(t *testing.T) {
		v := verify(models.Trajectory{claimAt(5, models.FileOpen, out)},
			agentEv(1, models.FileWrite, out), withHash(agentEv(2, models.FileClose, out), nil, h),
			agentEv(5, models.FileOpen, out), agentEv(6, models.FileOpen, out))
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.Corroborated) != 1 || v.Findings() != 0 || len(v.UnexplainedHarness) != 0 || len(v.Coverage.UnexplainedActions) != 0 {
			t.Errorf("corroborated=%d findings=%d unrecorded=%v harness=%v coverage=%v",
				len(v.Corroborated), v.Findings(), v.Unrecorded, v.UnexplainedHarness, v.Coverage.UnexplainedActions)
		}
	})
	t.Run("an unclaimed path is subtracted as before", func(t *testing.T) {
		v := verify(models.Trajectory{claimAt(5, models.FileOpen, "/w/a")}, agentEv(1, models.FileWrite, out), agentEv(5, models.FileOpen, "/w/a"))
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.Corroborated) != 1 {
			t.Errorf("corroborated=%d", len(v.Corroborated))
		}
	})
	t.Run("an out-of-scope claim keeps nothing", func(t *testing.T) {
		v := Verify(Input{Claims: models.Trajectory{claimAt(5, models.FileOpen, out)}, Ground: models.GroundTruth{agentEv(5, models.FileOpen, out)},
			RootPID: agentPID, Coverage: completeCov(), Baseline: base, Workspace: "/w"})
		wantOutcome(t, v, OutcomeInconclusive)
		if len(v.OutOfScope) != 1 || len(v.Corroborated) != 0 || v.Findings() != 0 {
			t.Errorf("out of scope=%v corroborated=%d findings=%d", v.OutOfScope, len(v.Corroborated), v.Findings())
		}
	})
	// The price, stated in V-30: a fabricated claim of a read of a file the
	// harness itself read is corroborated by the harness's open, which the
	// verifier cannot tell from the agent's. A fabricated write still has to
	// match the observed content.
	t.Run("a fabricated read of a baselined path is corroborated", func(t *testing.T) {
		v := verify(models.Trajectory{claimAt(5, models.FileOpen, out)}, agentEv(1, models.FileOpen, out))
		wantOutcome(t, v, OutcomeFaithful)
	})
	t.Run("a fabricated write of a baselined path must match its content", func(t *testing.T) {
		claimed := withClaimHash(claimAt(5, models.FileWrite, out), nil, sp("sha256:fake"))
		v := verify(models.Trajectory{claimed}, withHash(agentEv(1, models.FileWrite, out), nil, h))
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Mismatched) != 1 || v.Mismatched[0].Diffs[0] != DiffOutputHash {
			t.Errorf("mismatched=%v", v.Mismatched)
		}
	})
}

// V-36: a corroborated read whose open the baseline also explains is listed
// in CorroboratedHarnessShared as well as in Corroborated, since the open
// cannot be told apart from the harness's own read of the file. The list
// changes no outcome and no finding count.
func TestVerify_AReadPairedWithABaselineOpenIsListedAsHarnessShared(t *testing.T) {
	const (
		cfg   = "/home/u/.claude/settings.json"
		plain = "/w/a"
	)
	base := func(e models.GroundTruthEvent) bool { return e.Target == cfg }
	verify := func(b Baseline, claims models.Trajectory, g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: b})
	}
	cases := []struct {
		name         string
		claims       models.Trajectory
		ground       models.GroundTruth
		outcome      Outcome
		shared       []string
		corroborated int
	}{
		{
			name:   "a claimed read paired with a baseline-matched open is listed",
			claims: models.Trajectory{claimAt(5, models.FileOpen, cfg)},
			ground: models.GroundTruth{agentEv(5, models.FileOpen, cfg)}, outcome: OutcomeFaithful,
			shared: []string{cfg}, corroborated: 1,
		},
		{
			// The cost V-30 records, now visible: the harness's own open
			// corroborates a read the agent never made.
			name:   "a fabricated read paired with the harness's open is listed",
			claims: models.Trajectory{claimAt(5, models.FileOpen, cfg)},
			ground: models.GroundTruth{agentEv(1, models.FileOpen, cfg)}, outcome: OutcomeFaithful,
			shared: []string{cfg}, corroborated: 1,
		},
		{
			name:   "a claimed read of a file the baseline does not hold is not listed",
			claims: models.Trajectory{claimAt(5, models.FileOpen, plain)},
			ground: models.GroundTruth{agentEv(1, models.FileOpen, cfg), agentEv(5, models.FileOpen, plain)}, outcome: OutcomeFaithful,
			corroborated: 1,
		},
		{
			// A write is checked on its content, so it is not listed.
			name:   "a corroborated write on a baselined path is not listed",
			claims: models.Trajectory{withClaimHash(claimAt(5, models.FileWrite, cfg), nil, sp("sha256:cc"))},
			ground: models.GroundTruth{withHash(agentEv(5, models.FileWrite, cfg), nil, sp("sha256:cc"))}, outcome: OutcomeFaithful,
			corroborated: 1,
		},
		{
			// A read whose stated content differs from the kept open is a
			// Mismatched finding, not a corroboration, and is not listed.
			name:   "a mismatched read of a baselined path is not listed",
			claims: models.Trajectory{withClaimHash(claimAt(5, models.FileOpen, cfg), sp("sha256:claimed"), nil)},
			ground: models.GroundTruth{withHash(agentEv(5, models.FileOpen, cfg), sp("sha256:observed"), nil)}, outcome: OutcomeNotFaithful,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := verify(base, tc.claims, tc.ground...)
			wantOutcome(t, v, tc.outcome)
			var got []string
			for _, p := range v.CorroboratedHarnessShared {
				got = append(got, p.Event.Target)
				if !containsPair(v.Corroborated, p) {
					t.Errorf("shared pair %v is not also corroborated", p)
				}
			}
			if strings.Join(got, ",") != strings.Join(tc.shared, ",") || len(v.Corroborated) != tc.corroborated {
				t.Errorf("shared=%v corroborated=%d, want %v and %d", got, len(v.Corroborated), tc.shared, tc.corroborated)
			}
		})
	}
	// Without a baseline nothing is shared and the honest read's outcome is
	// the same: the list only annotates.
	v := verify(nil, cases[0].claims, cases[0].ground...)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.CorroboratedHarnessShared) != 0 || len(v.Corroborated) != 1 {
		t.Errorf("without a baseline: shared=%v corroborated=%d", v.CorroboratedHarnessShared, len(v.Corroborated))
	}
}

// V-37: a level-0 write the baseline explains is listed when its path lies
// outside the harness's declared directories, since an unclaimed write by the
// agent there would be hidden by the rule. A write under the declared
// directories, a write a claim paired with, a command's write and a write no
// rule explains are not listed. The list changes no outcome.
func TestVerify_BaselinedWritesOutsideTheHarnessDirectoriesAreListed(t *testing.T) {
	const (
		sock  = "/tmp/cc-socks"
		cfg   = "/home/u/.harness/state.json"
		plain = "/w/a"
	)
	base := func(e models.GroundTruthEvent) bool {
		return e.Target == sock || e.Target == cfg || e.Target == "/bin/sh -c probe"
	}
	owned := func(p string) bool { return strings.HasPrefix(p, "/home/u/.harness/") }
	cases := []struct {
		name    string
		owned   func(string) bool
		b       Baseline
		claims  models.Trajectory
		ground  models.GroundTruth
		outcome Outcome
		listed  []string
	}{
		{
			name: "a baselined write outside the declared directories is listed", owned: owned, b: base,
			ground:  models.GroundTruth{agentEv(1, models.FileWrite, sock), agentEv(2, models.FileDelete, sock), agentEv(3, models.FileOpen, sock)},
			outcome: OutcomeFaithful, listed: []string{"file_write " + sock, "file_delete " + sock},
		},
		{
			name: "a baselined write under the declared directories is not listed", owned: owned, b: base,
			ground:  models.GroundTruth{agentEv(1, models.FileWrite, cfg), agentEv(2, models.FileClose, cfg)},
			outcome: OutcomeFaithful,
		},
		{
			name: "with no declaration every baselined write is listed", b: base,
			ground:  models.GroundTruth{agentEv(1, models.FileWrite, cfg), agentEv(2, models.FileWrite, sock)},
			outcome: OutcomeFaithful, listed: []string{"file_write " + cfg, "file_write " + sock},
		},
		{
			// A claimed write pairs with the kept event and is checked on its
			// content (V-30), so it is not listed.
			name: "a baselined write a claim paired with is not listed", owned: owned, b: base,
			claims:  models.Trajectory{withClaimHash(claimAt(1, models.FileWrite, sock), nil, sp("sha256:aa"))},
			ground:  models.GroundTruth{withHash(agentEv(1, models.FileWrite, sock), nil, sp("sha256:aa"))},
			outcome: OutcomeFaithful,
		},
		{
			// The write is kept for the read claim on its path and stays
			// unpaired: explained by the baseline, and listed.
			name: "a kept baselined write that stays unpaired is listed", owned: owned, b: base,
			claims:  models.Trajectory{claimAt(1, models.FileOpen, sock)},
			ground:  models.GroundTruth{agentEv(1, models.FileOpen, sock), agentEv(2, models.FileWrite, sock)},
			outcome: OutcomeFaithful, listed: []string{"file_write " + sock},
		},
		{
			name: "a baselined command's write is not a level-0 write", owned: owned, b: base,
			ground: models.GroundTruth{
				fork(1, 200, agentPID), execEv(2, 200, agentPID, "/bin/sh -c probe"), fsEv(3, 200, sock),
				exitEv(4, 200, agentPID, "/bin/sh -c probe"),
			},
			outcome: OutcomeFaithful,
		},
		{
			name: "a write no rule explains is a finding, not listed", owned: owned, b: base,
			ground:  models.GroundTruth{agentEv(1, models.FileWrite, plain)},
			outcome: OutcomeNotFaithful,
		},
		{
			name: "without a baseline nothing is listed", owned: owned,
			ground:  models.GroundTruth{agentEv(1, models.FileWrite, cfg)},
			outcome: OutcomeInconclusive,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Verify(Input{Claims: tc.claims, Ground: tc.ground, RootPID: agentPID, Coverage: completeCov(), Baseline: tc.b, Options: Options{HarnessOwned: tc.owned}})
			wantOutcome(t, v, tc.outcome)
			var got []string
			for _, e := range v.BaselinedWritesOutsideHarness {
				got = append(got, string(e.ActionType)+" "+e.Target)
			}
			if strings.Join(got, ",") != strings.Join(tc.listed, ",") {
				t.Errorf("listed %v, want %v", got, tc.listed)
			}
		})
	}
}

func containsPair(pairs []MatchedPair, p MatchedPair) bool {
	for _, q := range pairs {
		if q.Entry.Target == p.Entry.Target && q.Entry.ActionType == p.Entry.ActionType && q.Event.Timestamp.Equal(p.Event.Timestamp) && q.Event.Target == p.Event.Target {
			return true
		}
	}
	return false
}

// O-28, decided as V-29: the fs probe states no input hash for a file it never
// measured (P-22), so an Edit's stated input on such a file is unverified and the
// run INCONCLUSIVE, never a mismatch against a stamp. A stated input that
// differs from a hash the probe really computed is still a finding.
func TestAStatedInputTheProbeDidNotMeasureIsUnverified(t *testing.T) {
	claim := claimAt(0, models.FileOpen, "/home/u/.config/app/settings.json")
	claim.InputHash = sp("sha256:the-file-as-it-really-was")
	unmeasured := agentEv(0, models.FileOpen, "/home/u/.config/app/settings.json")

	v := run(models.Trajectory{claim}, models.GroundTruth{unmeasured})
	wantOutcome(t, v, OutcomeInconclusive)
	if len(v.Mismatched) != 0 || len(v.Unverified) != 1 || v.Unverified[0].Diffs[0] != DiffInputHash {
		t.Errorf("mismatched=%v unverified=%+v, want the input_hash unverified and no finding", v.Mismatched, v.Unverified)
	}

	measured := unmeasured
	measured.InputHash = sp("sha256:what-the-probe-read")
	v = run(models.Trajectory{claim}, models.GroundTruth{measured})
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.Mismatched) != 1 || v.Mismatched[0].Diffs[0] != DiffInputHash {
		t.Errorf("Mismatched = %v, want the input_hash", v.Mismatched)
	}
}

// V-31, the shape of the second tools capture: an honest Read of a background
// task's output file, and a later harness open of the same canonical path that
// the baseline holds. Both events pair with the claim at the same cost; the one
// inside the claim's interval is chosen, and the other stays baselined.
func TestVerify_AnHonestReadPairsWithTheOpenInsideItsInterval(t *testing.T) {
	const out = "/tmp/claude-1000/w/SESSION/tasks/N.output"
	base := func(e models.GroundTruthEvent) bool { return e.Target == out }
	c := claimAt(5, models.FileOpen, out)
	end := at(10)
	c.End = &end
	v := Verify(Input{Claims: models.Trajectory{c}, Ground: models.GroundTruth{agentEv(6, models.FileOpen, out), agentEv(50, models.FileOpen, out)},
		RootPID: agentPID, Coverage: completeCov(), Baseline: base})
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Corroborated) != 1 || !v.Corroborated[0].Event.Timestamp.Equal(at(6)) || len(v.OutsideInterval) != 0 || !v.Ambiguous {
		t.Errorf("corroborated=%v outside=%v ambiguous=%v", v.Corroborated, v.OutsideInterval, v.Ambiguous)
	}
}

// I-41: the baseline predicate may recognise a family of paths (a Claude
// Code baseline sees each event in its canonical form, so every task's output
// file matches one rule), but the claimed-path test of V-30 and the pairing
// compare exact targets. Only the event on the path the claim names is kept;
// another member of the family is subtracted and cannot pair with the claim.
func TestVerify_ABaselineFamilyKeepsOnlyTheClaimedPath(t *testing.T) {
	const (
		own   = "/tmp/claude-1000/w/s1/tasks/a1.output"
		other = "/tmp/claude-1000/w/s1/tasks/b2.output"
	)
	family := func(e models.GroundTruthEvent) bool {
		return strings.HasPrefix(e.Target, "/tmp/claude-1000/w/s1/tasks/") && strings.HasSuffix(e.Target, ".output")
	}
	verify := func(g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: models.Trajectory{claimAt(5, models.FileOpen, own)}, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: family})
	}

	t.Run("the claim pairs with its own file and the other is subtracted", func(t *testing.T) {
		v := verify(agentEv(5, models.FileOpen, own), agentEv(6, models.FileOpen, other))
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.Corroborated) != 1 || v.Corroborated[0].Event.Target != own || v.Ambiguous {
			t.Errorf("corroborated=%v ambiguous=%v", v.Corroborated, v.Ambiguous)
		}
		for _, la := range v.Alignments {
			for _, e := range la.Edits {
				if e.Event != nil && e.Event.Target == other {
					t.Errorf("the other task's output was aligned: %+v", e)
				}
			}
		}
	})
	t.Run("another task's output does not witness the claim", func(t *testing.T) {
		v := verify(agentEv(5, models.FileOpen, other))
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unwitnessed) != 1 || len(v.Corroborated) != 0 || len(v.Mismatched) != 0 || len(v.Unrecorded) != 0 {
			t.Errorf("unwitnessed=%v corroborated=%v mismatched=%v unrecorded=%v", v.Unwitnessed, v.Corroborated, v.Mismatched, v.Unrecorded)
		}
	})
}

// Coverage.BaselinedLevelZero counts the agent process's own events the
// baseline explains: those subtracted before alignment and those kept for a
// claim on their path that stayed unpaired (V-30). The baseline commands'
// subtrees are counted in Baselined, apart.
func TestVerify_BaselinedLevelZeroCountsTheAgentProcessesOwnEvents(t *testing.T) {
	const out = "/tmp/h/tasks/N.output"
	base := func(e models.GroundTruthEvent) bool {
		return e.Target == out || e.Target == "/home/u/.config/agent.json" || e.Target == "/usr/bin/telemetry"
	}
	g := models.GroundTruth{
		agentEv(1, models.FileOpen, "/home/u/.config/agent.json"), // subtracted
		agentEv(2, models.FileWrite, out),                         // kept for the claim, unpaired
		agentEv(3, models.FileOpen, out),                          // pairs with the claim
		fork(4, 200, agentPID), execEv(5, 200, agentPID, "/usr/bin/telemetry"),
		fsEv(6, 200, "/var/log/telemetry"), // beneath the baseline command
	}
	v := Verify(Input{Claims: models.Trajectory{claimAt(3, models.FileOpen, out)}, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: base})
	wantOutcome(t, v, OutcomeFaithful)
	if v.Coverage.BaselinedLevelZero != 2 || v.Coverage.Baselined != 1 {
		t.Errorf("baselined at level 0 = %d, want 2; beneath baseline commands = %d, want 1", v.Coverage.BaselinedLevelZero, v.Coverage.Baselined)
	}
}
