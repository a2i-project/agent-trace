package verification

import (
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

func TestVerify_OutsideEventsAreReportedAndDoNotBlock(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.FileWrite, "/w/a"), fsEv(1, 7777, "/w/stranger")}
	v := run(models.Trajectory{claimAt(0, models.FileWrite, "/w/a")}, g)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Coverage.Outside) != 1 {
		t.Errorf("Outside = %d, want 1 reported", len(v.Coverage.Outside))
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
	const n = 4200 // n*n exceeds the alignment budget
	var g models.GroundTruth
	var tr models.Trajectory
	for i := 0; i < n; i++ {
		g = append(g, agentEv(i, models.FileWrite, "/w/a"))
		tr = append(tr, claimAt(i, models.FileWrite, "/w/a"))
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
