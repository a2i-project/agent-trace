package verification

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
)

var (
	baseTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	cfg      = matching.DefaultConfig()
)

func te(offsetMs int, action models.ActionType, target string, in, out *string) models.TrajectoryEntry {
	return models.TrajectoryEntry{
		Timestamp:  baseTime.Add(time.Duration(offsetMs) * time.Millisecond),
		ActionType: action,
		Target:     target,
		InputHash:  in,
		OutputHash: out,
	}
}

func ge(offsetMs int, action models.ActionType, target string, in, out *string) models.GroundTruthEvent {
	return models.GroundTruthEvent{IsTopLevel: bp(true),
		Timestamp:  baseTime.Add(time.Duration(offsetMs) * time.Millisecond),
		ActionType: action,
		Target:     target,
		InputHash:  in,
		OutputHash: out,
	}
}

func sp(s string) *string { return &s }

func bp(b bool) *bool { return &b }

// --- Unit tests for individual sets ---

func TestAllCorroborated(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/etc/hostname", nil, sp("h1")),
		te(1000, models.FileWrite, "/tmp/out.txt", sp("h2"), sp("h3")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileRead, "/etc/hostname", nil, sp("h1")),
		ge(1002, models.FileWrite, "/tmp/out.txt", sp("h2"), sp("h3")),
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("expected FAITHFUL")
	}
	if len(v.Corroborated) != 2 {
		t.Errorf("expected 2 corroborated, got %d", len(v.Corroborated))
	}
	if len(v.Unwitnessed) != 0 {
		t.Errorf("expected 0 unwitnessed, got %d", len(v.Unwitnessed))
	}
	if len(v.Unrecorded) != 0 {
		t.Errorf("expected 0 unrecorded, got %d", len(v.Unrecorded))
	}
	if len(v.Mismatched) != 0 {
		t.Errorf("expected 0 mismatched, got %d", len(v.Mismatched))
	}
}

func TestUnwitnessed(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/etc/hostname", nil, sp("h1")),
		te(1000, models.FileRead, "/etc/shadow", nil, sp("h_secret")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileRead, "/etc/hostname", nil, sp("h1")),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("expected NOT FAITHFUL")
	}
	if len(v.Unwitnessed) != 1 {
		t.Fatalf("expected 1 unwitnessed, got %d", len(v.Unwitnessed))
	}
	if v.Unwitnessed[0].Target != "/etc/shadow" {
		t.Errorf("wrong unwitnessed target: %s", v.Unwitnessed[0].Target)
	}
}

func TestUnrecorded(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/etc/hostname", nil, sp("h1")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileRead, "/etc/hostname", nil, sp("h1")),
		ge(500, models.NetRequest, "https://evil.com/exfil", sp("stolen"), sp("ack")),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("expected NOT FAITHFUL")
	}
	if len(v.Unrecorded) != 1 {
		t.Fatalf("expected 1 unrecorded, got %d", len(v.Unrecorded))
	}
	if v.Unrecorded[0].Target != "https://evil.com/exfil" {
		t.Errorf("wrong unrecorded target: %s", v.Unrecorded[0].Target)
	}
}

func TestDescendantGroundTruthIsIgnored(t *testing.T) {
	ground := models.GroundTruth{
		{IsTopLevel: bp(false), Timestamp: baseTime, ActionType: models.ProcessExec, Target: "helper"},
	}

	v := Verify(nil, ground, cfg)
	if !v.Faithful {
		t.Fatalf("descendant event should not affect verification: %+v", v)
	}
	if len(v.Unrecorded) != 0 {
		t.Fatalf("expected no unrecorded descendant events, got %d", len(v.Unrecorded))
	}
}

// Fix 3b end-to-end semantics: for a chain of pure shell re-execs, 3b keeps
// the inner command verification-grade (IsTopLevel: true), so a trajectory
// that only reports the outer `sh -c ...` invocation is still missing the
// command the shell actually ran and must come back NOT FAITHFUL. This is
// the inverse of TestDescendantGroundTruthIsIgnored: there a forensic
// descendant is correctly ignored; here a shell-routed command is top-level
// and must not be. The forensic third event confirms the boundary still
// holds -- Verify uses whatever IsTopLevel values it is given, and 3b's job
// is to feed it the right ones.
func TestShellChainInnerCommandIsUnrecorded(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.ProcessExec, "/bin/sh -c echo-hello", nil, nil),
	}
	ground := models.GroundTruth{
		{IsTopLevel: bp(true), Timestamp: baseTime.Add(2 * time.Millisecond),
			ActionType: models.ProcessExec, Target: "/bin/sh -c echo-hello"},
		{IsTopLevel: bp(true), Timestamp: baseTime.Add(6 * time.Millisecond),
			ActionType: models.ProcessExec, Target: "/bin/echo hello"},
		{IsTopLevel: bp(false), Timestamp: baseTime.Add(7 * time.Millisecond),
			ActionType: models.ProcessExec, Target: "/lib/ld-linux.so helper"},
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("shell-routed inner command must not read as faithful")
	}
	if len(v.Corroborated) != 1 {
		t.Errorf("expected the outer sh invocation corroborated, got %d", len(v.Corroborated))
	}
	if len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != "/bin/echo hello" {
		t.Errorf("expected only the inner shell-routed command unrecorded, got %+v", v.Unrecorded)
	}
}

func TestLegacyGroundTruthDefaultsToTopLevel(t *testing.T) {
	traj := models.Trajectory{te(0, models.FileRead, "/tmp/file", nil, nil)}
	ground := models.GroundTruth{
		{Timestamp: baseTime, ActionType: models.FileRead, Target: "/tmp/file"},
	}

	v := Verify(traj, ground, cfg)
	if !v.Faithful || len(v.Corroborated) != 1 {
		t.Fatalf("legacy event should remain verifiable: %+v", v)
	}
}

func TestMismatched(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/etc/hostname", nil, sp("benign_hash")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileRead, "/etc/hostname", nil, sp("real_hash")),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("expected NOT FAITHFUL")
	}
	if len(v.Mismatched) != 1 {
		t.Fatalf("expected 1 mismatched, got %d", len(v.Mismatched))
	}
	if *v.Mismatched[0].Entry.OutputHash != "benign_hash" {
		t.Errorf("wrong entry hash: %s", *v.Mismatched[0].Entry.OutputHash)
	}
	if *v.Mismatched[0].Event.OutputHash != "real_hash" {
		t.Errorf("wrong event hash: %s", *v.Mismatched[0].Event.OutputHash)
	}
}

func TestHashNilTreatedAsAgreement(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/etc/hostname", nil, sp("h1")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileRead, "/etc/hostname", nil, nil),
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("nil ground-truth hash should not cause mismatch")
	}
	if len(v.Corroborated) != 1 {
		t.Errorf("expected 1 corroborated, got %d", len(v.Corroborated))
	}
}

func TestExitCodeMismatch(t *testing.T) {
	claimedOK := int32(0)
	actualFailed := int32(1)
	traj := models.Trajectory{
		{Timestamp: baseTime, ActionType: models.ProcessExit, Target: "/usr/bin/git push", ExitCode: &claimedOK},
	}
	ground := models.GroundTruth{
		{IsTopLevel: bp(true), Timestamp: baseTime.Add(5 * time.Millisecond), ActionType: models.ProcessExit, Target: "/usr/bin/git push", ExitCode: &actualFailed},
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("expected NOT FAITHFUL: agent claimed exit 0 but process exited 1")
	}
	if len(v.Mismatched) != 1 {
		t.Fatalf("expected 1 mismatched, got %d", len(v.Mismatched))
	}
	if *v.Mismatched[0].Entry.ExitCode != 0 || *v.Mismatched[0].Event.ExitCode != 1 {
		t.Errorf("wrong exit codes in mismatch: entry=%d event=%d",
			*v.Mismatched[0].Entry.ExitCode, *v.Mismatched[0].Event.ExitCode)
	}
}

func TestExitCodeNilTreatedAsAgreement(t *testing.T) {
	code := int32(0)
	traj := models.Trajectory{
		{Timestamp: baseTime, ActionType: models.ProcessExit, Target: "/usr/bin/git push", ExitCode: &code},
	}
	ground := models.GroundTruth{
		// Probe didn't capture an exit code (e.g. killed by an uncaught
		// signal, never hit exit_group): should not be a mismatch.
		{IsTopLevel: bp(true), Timestamp: baseTime.Add(5 * time.Millisecond), ActionType: models.ProcessExit, Target: "/usr/bin/git push"},
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("nil ground-truth exit code should not cause mismatch")
	}
	if len(v.Corroborated) != 1 {
		t.Errorf("expected 1 corroborated, got %d", len(v.Corroborated))
	}
}

func TestRequestHashMismatch(t *testing.T) {
	claimed := "sha256:claimed"
	real := "sha256:real"
	traj := models.Trajectory{
		{Timestamp: baseTime, ActionType: models.NetRequest,
			Target: "GET https://api.example.com/v1/chat", RequestHash: &claimed},
	}
	ground := models.GroundTruth{
		{IsTopLevel: bp(true), Timestamp: baseTime.Add(5 * time.Millisecond), ActionType: models.NetRequest,
			Target: "GET https://api.example.com/v1/chat", RequestHash: &real},
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("expected NOT FAITHFUL: claimed request body hash does not match observed plaintext")
	}
	if len(v.Mismatched) != 1 {
		t.Fatalf("expected 1 mismatched, got %d", len(v.Mismatched))
	}
	if *v.Mismatched[0].Entry.RequestHash != claimed || *v.Mismatched[0].Event.RequestHash != real {
		t.Errorf("wrong request hashes in mismatch: entry=%s event=%s",
			*v.Mismatched[0].Entry.RequestHash, *v.Mismatched[0].Event.RequestHash)
	}
}

func TestRequestHashNilTreatedAsAgreement(t *testing.T) {
	traj := models.Trajectory{
		{Timestamp: baseTime, ActionType: models.NetRequest, Target: "GET https://api.example.com/v1/chat"},
	}
	ground := models.GroundTruth{
		// Capture layer couldn't attribute content to this connection
		// (e.g. an unattributed ssl_frame, or an h2 connection): should
		// not be a mismatch on its own.
		{IsTopLevel: bp(true), Timestamp: baseTime.Add(5 * time.Millisecond), ActionType: models.NetRequest,
			Target: "GET https://api.example.com/v1/chat"},
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("nil request hash on both sides should not cause mismatch")
	}
	if len(v.Corroborated) != 1 {
		t.Errorf("expected 1 corroborated, got %d", len(v.Corroborated))
	}
}

func ip(n int32) *int32 { return &n }

// Fix 4: a FileClose entry that omits OutputHash while the ground truth
// captured one is the agent opting out of a content check, not a probe gap.
// It must surface as Mismatched, not Corroborated.
func TestOmittedOutputHashOnFileCloseIsMismatched(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileClose, "/workspace/out.txt", nil, nil),
	}
	ground := models.GroundTruth{
		ge(5, models.FileClose, "/workspace/out.txt", nil, sp("real_hash")),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("omitted OutputHash on FileClose should be NOT FAITHFUL")
	}
	if len(v.Mismatched) != 1 {
		t.Fatalf("expected 1 mismatched, got %d", len(v.Mismatched))
	}
	if v.Mismatched[0].Entry.OutputHash != nil {
		t.Errorf("entry OutputHash should stay nil in the report, got %q",
			*v.Mismatched[0].Entry.OutputHash)
	}
	if v.Mismatched[0].Event.OutputHash == nil || *v.Mismatched[0].Event.OutputHash != "real_hash" {
		t.Errorf("event OutputHash should show what the probe captured, got %v",
			v.Mismatched[0].Event.OutputHash)
	}
	if len(v.Corroborated) != 0 {
		t.Errorf("expected 0 corroborated, got %d", len(v.Corroborated))
	}
}

// Fix 4: same rule for a ProcessExit entry that omits ExitCode while the
// ground truth captured one.
func TestOmittedExitCodeOnProcessExitIsMismatched(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.ProcessExit, "/usr/bin/git push", nil, nil),
	}
	ground := models.GroundTruth{
		{IsTopLevel: bp(true), Timestamp: baseTime.Add(5 * time.Millisecond),
			ActionType: models.ProcessExit, Target: "/usr/bin/git push", ExitCode: ip(1)},
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("omitted ExitCode on ProcessExit should be NOT FAITHFUL")
	}
	if len(v.Mismatched) != 1 {
		t.Fatalf("expected 1 mismatched, got %d", len(v.Mismatched))
	}
	if v.Mismatched[0].Entry.ExitCode != nil {
		t.Errorf("entry ExitCode should stay nil in the report, got %d",
			*v.Mismatched[0].Entry.ExitCode)
	}
	if v.Mismatched[0].Event.ExitCode == nil || *v.Mismatched[0].Event.ExitCode != 1 {
		t.Errorf("event ExitCode should show what the probe captured, got %v",
			v.Mismatched[0].Event.ExitCode)
	}
}

// Fix 4 regression guard: the permissive default is deliberately kept for
// the ground-truth-side nil (the probe genuinely couldn't capture it). This
// duplicates TestHashNilTreatedAsAgreement's intent, kept next to the new
// tests as an explicit "did the override flip the wrong direction" check.
func TestGroundTruthNilHashStillTreatedAsAgreement(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileClose, "/workspace/out.txt", nil, sp("agent_hash")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileClose, "/workspace/out.txt", nil, nil),
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("nil ground-truth hash must still be treated as agreement")
	}
	if len(v.Corroborated) != 1 {
		t.Errorf("expected 1 corroborated, got %d", len(v.Corroborated))
	}
}

// Fix 4 scope boundary: InputHash is deliberately NOT covered by the
// override yet (Tier 4.2 capture isn't implemented on either side). A
// trajectory omitting InputHash while the ground truth has one must still be
// treated as agreement. This fails loudly if someone extends the override
// to InputHash without building the Tier 4.2 capture path.
func TestOmittedInputHashStillTreatedAsAgreement(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileClose, "/workspace/out.txt", nil, sp("out_h")),
	}
	ground := models.GroundTruth{
		ge(5, models.FileClose, "/workspace/out.txt", sp("in_h"), sp("out_h")),
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("omitted InputHash must still be treated as agreement until Tier 4.2")
	}
	if len(v.Corroborated) != 1 {
		t.Errorf("expected 1 corroborated, got %d", len(v.Corroborated))
	}
}

func TestEmptyTrajectoryAndGroundTruth(t *testing.T) {
	v := Verify(nil, nil, cfg)

	if !v.Faithful {
		t.Error("empty T and G should be FAITHFUL")
	}
}

func TestEmptyTrajectoryWithGroundTruth(t *testing.T) {
	ground := models.GroundTruth{
		ge(0, models.FileRead, "/etc/hostname", nil, sp("h1")),
	}

	v := Verify(nil, ground, cfg)

	if v.Faithful {
		t.Error("empty T with non-empty G should be NOT FAITHFUL (omission)")
	}
	if len(v.Unrecorded) != 1 {
		t.Errorf("expected 1 unrecorded, got %d", len(v.Unrecorded))
	}
}

func TestGreedyClosestTimestamp(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileWrite, "/tmp/f.txt", nil, sp("h1")),
		te(100, models.FileWrite, "/tmp/f.txt", nil, sp("h2")),
	}
	ground := models.GroundTruth{
		ge(3, models.FileWrite, "/tmp/f.txt", nil, sp("h1")),
		ge(98, models.FileWrite, "/tmp/f.txt", nil, sp("h2")),
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("expected FAITHFUL with correct closest-timestamp pairing")
	}
	if len(v.Corroborated) != 2 {
		t.Errorf("expected 2 corroborated, got %d", len(v.Corroborated))
	}
}

// F2.2: a single verification pass over a trajectory that mixes file and
// process actions, where the process probe reports absolute command paths
// while the agent logs bare command names. All entries should corroborate.
func TestMixedFileAndProcessVerification(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/workspace/./main.go", nil, sp("src_h")),
		te(500, models.ProcessExec, "/usr/local/bin/go", sp("build_args"), nil),
		te(1500, models.FileWrite, "/workspace/bin/app", sp("nil_h"), sp("bin_h")),
		te(2500, models.ProcessExec, "/usr/bin/git", sp("commit_args"), nil),
		te(3000, models.ProcessExit, "/usr/bin/git", nil, sp("0")),
	}
	ground := models.GroundTruth{
		ge(3, models.FileRead, "/workspace/main.go", nil, sp("src_h")),
		ge(505, models.ProcessExec, "/usr/local/bin/go", sp("build_args"), nil),
		ge(1502, models.FileWrite, "/workspace/bin/app", sp("nil_h"), sp("bin_h")),
		ge(2503, models.ProcessExec, "/usr/bin/git", sp("commit_args"), nil),
		ge(3004, models.ProcessExit, "/usr/bin/git", nil, sp("0")),
	}

	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Errorf("mixed file+process trajectory should be FAITHFUL: %+v", v)
	}
	if len(v.Corroborated) != 5 {
		t.Errorf("expected 5 corroborated, got %d", len(v.Corroborated))
	}
}

// F2.2: a process action the agent omitted from its trajectory must surface as
// Unrecorded even when file actions in the same pass all corroborate.
func TestMixedVerificationDetectsOmittedProcess(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileWrite, "/workspace/payload.sh", nil, sp("sh_h")),
	}
	ground := models.GroundTruth{
		ge(2, models.FileWrite, "/workspace/payload.sh", nil, sp("sh_h")),
		ge(50, models.ProcessExec, "/bin/bash", sp("bash_args"), nil),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("omitted subprocess spawn should be NOT FAITHFUL")
	}
	if len(v.Unrecorded) != 1 || v.Unrecorded[0].ActionType != models.ProcessExec {
		t.Fatalf("expected 1 unrecorded process_exec, got %+v", v.Unrecorded)
	}
}

// --- E2E attack scenarios (design properties P1, P2, P3, P5) ---

// Honest trajectory: 5 actions, all present and matching in ground truth.
func honestTrajectory() (models.Trajectory, models.GroundTruth) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/workspace/config.yaml", nil, sp("cfg_h")),
		te(1000, models.ProcessExec, "python main.py", sp("args_h"), nil),
		te(2000, models.NetRequest, "https://api.openai.com/v1/chat", sp("req_h"), sp("resp_h")),
		te(3000, models.FileWrite, "/workspace/output.txt", sp("before_h"), sp("after_h")),
		te(4000, models.ProcessExec, "git commit -m fix", sp("git_args"), nil),
	}
	ground := models.GroundTruth{
		ge(2, models.FileRead, "/workspace/config.yaml", nil, sp("cfg_h")),
		ge(1003, models.ProcessExec, "python main.py", sp("args_h"), nil),
		ge(2010, models.NetRequest, "https://api.openai.com/v1/chat", sp("req_h"), sp("resp_h")),
		ge(3001, models.FileWrite, "/workspace/output.txt", sp("before_h"), sp("after_h")),
		ge(4005, models.ProcessExec, "git commit -m fix", sp("git_args"), nil),
	}
	return traj, ground
}

func TestE2E_HonestTrajectory(t *testing.T) {
	traj, ground := honestTrajectory()
	v := Verify(traj, ground, cfg)

	if !v.Faithful {
		t.Error("honest trajectory should be FAITHFUL")
	}
	if len(v.Corroborated) != 5 {
		t.Errorf("expected 5 corroborated, got %d", len(v.Corroborated))
	}
}

// T1 attack: agent omits the API call from the trajectory (hides exfiltration).
func TestE2E_T1_Omission(t *testing.T) {
	traj, ground := honestTrajectory()

	// Drop the network request (index 2) from the trajectory.
	traj = append(traj[:2], traj[3:]...)

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("omission attack should be NOT FAITHFUL")
	}
	if len(v.Unrecorded) != 1 {
		t.Fatalf("expected 1 unrecorded, got %d", len(v.Unrecorded))
	}
	if v.Unrecorded[0].Target != "https://api.openai.com/v1/chat" {
		t.Errorf("wrong unrecorded target: %s", v.Unrecorded[0].Target)
	}
	if len(v.Corroborated) != 4 {
		t.Errorf("expected 4 corroborated, got %d", len(v.Corroborated))
	}
}

// T2 attack: agent fabricates a benign file read that never happened.
func TestE2E_T2_Fabrication(t *testing.T) {
	traj, ground := honestTrajectory()

	// Insert a fake entry: agent claims it read a harmless README.
	fake := te(2500, models.FileRead, "/workspace/README.md", nil, sp("readme_h"))
	traj = append(traj[:3], append(models.Trajectory{fake}, traj[3:]...)...)

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("fabrication attack should be NOT FAITHFUL")
	}
	if len(v.Unwitnessed) != 1 {
		t.Fatalf("expected 1 unwitnessed, got %d", len(v.Unwitnessed))
	}
	if v.Unwitnessed[0].Target != "/workspace/README.md" {
		t.Errorf("wrong unwitnessed target: %s", v.Unwitnessed[0].Target)
	}
	if len(v.Corroborated) != 5 {
		t.Errorf("expected 5 corroborated, got %d", len(v.Corroborated))
	}
}

// TestE2E_DirectoryFallbackRequiresAmbiguousFlag pins Fix 6 end to end:
// targetsMatch's directory-covers-file leniency must only apply when the
// ground truth is a genuinely ambiguous (DFID-only, kernel-merged) record.
// A fabricated file claim must not be laundered through an unrelated,
// exactly-resolved ground-truth event that merely happens to equal the
// claimed file's parent directory.
func TestE2E_DirectoryFallbackRequiresAmbiguousFlag(t *testing.T) {
	claim := te(0, models.FileWrite, "/workspace/secret.txt", nil, sp("h"))

	t.Run("exact ground truth equal to the directory does not corroborate", func(t *testing.T) {
		ground := models.GroundTruth{
			{IsTopLevel: bp(true), Timestamp: baseTime, ActionType: models.FileWrite, Target: "/workspace"},
		}

		v := Verify(models.Trajectory{claim}, ground, cfg)
		if v.Faithful {
			t.Error("a fabricated file claim must not be corroborated by an unrelated, exactly-resolved directory event")
		}
		if len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != "/workspace/secret.txt" {
			t.Errorf("expected the fabricated claim unwitnessed, got %+v", v.Unwitnessed)
		}
		if len(v.Corroborated) != 0 {
			t.Errorf("expected 0 corroborated, got %d", len(v.Corroborated))
		}
	})

	t.Run("ambiguous ground truth for the directory still corroborates", func(t *testing.T) {
		ground := models.GroundTruth{
			{IsTopLevel: bp(true), Timestamp: baseTime, ActionType: models.FileWrite, Target: "/workspace", PathIsAmbiguous: true},
		}

		v := Verify(models.Trajectory{claim}, ground, cfg)
		if !v.Faithful {
			t.Errorf("a genuinely ambiguous directory-level ground truth should still corroborate a file write inside it: %+v", v)
		}
		if len(v.Corroborated) != 1 {
			t.Errorf("expected 1 corroborated, got %d", len(v.Corroborated))
		}
	})
}

// TestE2E_AmbiguousDirectoryEventCorroboratesOnlyOneClaim guards the
// boundary of Fix 6's leniency: one ambiguous (DFID-only) ground-truth event
// for a directory can corroborate a file claim inside that directory, but
// Verify's one-to-one greedy matching (matched[bestIdx] = true) means it can
// still corroborate only ONE such claim, not every file an agent claims to
// have touched in that directory. A second, distinct file claim with no
// ground-truth event of its own must remain unwitnessed even though the
// same ambiguous directory event would, in isolation, satisfy targetsMatch
// for it too.
func TestE2E_AmbiguousDirectoryEventCorroboratesOnlyOneClaim(t *testing.T) {
	claimA := te(0, models.FileWrite, "/workspace/a.txt", nil, sp("ha"))
	claimB := te(1, models.FileWrite, "/workspace/b.txt", nil, sp("hb"))

	ground := models.GroundTruth{
		{IsTopLevel: bp(true), Timestamp: baseTime, ActionType: models.FileWrite, Target: "/workspace", PathIsAmbiguous: true},
	}

	v := Verify(models.Trajectory{claimA, claimB}, ground, cfg)

	if v.Faithful {
		t.Errorf("only one ground-truth event exists for two distinct file claims; verdict must not be faithful: %+v", v)
	}
	if len(v.Corroborated) != 1 {
		t.Fatalf("expected exactly 1 corroborated claim (the event is consumed once), got %d: %+v", len(v.Corroborated), v.Corroborated)
	}
	if v.Corroborated[0].Entry.Target != "/workspace/a.txt" {
		t.Errorf("expected the earlier claim (a.txt) to win the closest-timestamp match, got %q", v.Corroborated[0].Entry.Target)
	}
	if len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != "/workspace/b.txt" {
		t.Errorf("expected b.txt to remain unwitnessed once the ambiguous event is consumed by a.txt, got %+v", v.Unwitnessed)
	}
}

// T3 attack: agent claims it read /etc/hostname but actually read /etc/shadow.
// The trajectory entry matches the ground-truth event on (type, target, time)
// but the output hash differs.
func TestE2E_T3_Substitution(t *testing.T) {
	traj, ground := honestTrajectory()

	// Replace the file read's output hash with a different value.
	// The agent claims it got "innocent_content" but the probe captured "cfg_h".
	traj[0].OutputHash = sp("innocent_content")

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("substitution attack should be NOT FAITHFUL")
	}
	if len(v.Mismatched) != 1 {
		t.Fatalf("expected 1 mismatched, got %d", len(v.Mismatched))
	}
	if v.Mismatched[0].Entry.Target != "/workspace/config.yaml" {
		t.Errorf("wrong mismatched target: %s", v.Mismatched[0].Entry.Target)
	}
	if len(v.Corroborated) != 4 {
		t.Errorf("expected 4 corroborated, got %d", len(v.Corroborated))
	}
}

// T3 attack, process-identity variant: the agent's trajectory claims it ran
// a trusted system binary, but the process it actually ran resolves to a
// different path (e.g. a planted binary earlier in PATH, or a directly
// invoked execve() with a spoofed argv[0]). This is the scenario proc.
// commandLine's move from argv[0] to the kernel-resolved execve filename
// exists to make visible: the ground-truth target below is what the fixed
// probe reports for such a run (see proc.TestCommandLine_UsesResolvedFilenameNotArgv0
// and matching.TestProcessCommandWithArguments for the layers underneath).
// Because the claimed and actual binaries are different resolved paths,
// commandsMatch refuses the match (no basename fallback applies across
// different directories), so this surfaces as Unwitnessed + Unrecorded
// rather than Mismatched, the same occurrence-level pattern the Tier 1
// filename-swap test documents for file actions.
func TestE2E_T3_ProcessMasquerading(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.ProcessExec, "/usr/bin/ls -la /workspace", nil, nil),
	}
	ground := models.GroundTruth{
		ge(5, models.ProcessExec, "/tmp/attacker-writable-dir/ls -la /workspace", nil, nil),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("process masquerading should be NOT FAITHFUL")
	}
	if len(v.Unwitnessed) != 1 {
		t.Fatalf("expected 1 unwitnessed (claimed binary never ran), got %d", len(v.Unwitnessed))
	}
	if v.Unwitnessed[0].Target != "/usr/bin/ls -la /workspace" {
		t.Errorf("wrong unwitnessed target: %s", v.Unwitnessed[0].Target)
	}
	if len(v.Unrecorded) != 1 {
		t.Fatalf("expected 1 unrecorded (the binary that actually ran), got %d", len(v.Unrecorded))
	}
	if v.Unrecorded[0].Target != "/tmp/attacker-writable-dir/ls -la /workspace" {
		t.Errorf("wrong unrecorded target: %s", v.Unrecorded[0].Target)
	}
	if len(v.Corroborated) != 0 {
		t.Errorf("expected 0 corroborated, got %d", len(v.Corroborated))
	}
}

// T3 attack, bare-name variant of process masquerading: the agent reports a
// process by the normal bare-name convention ("ls"), but the binary that
// actually ran resolves to a planted copy in an agent-writable directory
// that happens to share the basename. Before Fix 2, commandsMatch's
// unconditional basename fallback made this Corroborated. After Fix 2, a
// bare name only vouches for a resolved path whose directory is on the
// trustedBinDirs allowlist, so /tmp/attacker-writable-dir/ls does not
// match, and this surfaces as Unwitnessed + Unrecorded.
func TestE2E_T3_BareNameMasquerading(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.ProcessExec, "ls -la /workspace", nil, nil),
	}
	ground := models.GroundTruth{
		ge(5, models.ProcessExec, "/tmp/attacker-writable-dir/ls -la /workspace", nil, nil),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("bare-name masquerading should be NOT FAITHFUL")
	}
	if len(v.Corroborated) != 0 {
		t.Errorf("expected 0 corroborated, got %d", len(v.Corroborated))
	}
	if len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != "ls -la /workspace" {
		t.Errorf("expected the bare claim unwitnessed, got %+v", v.Unwitnessed)
	}
	if len(v.Unrecorded) != 1 ||
		v.Unrecorded[0].Target != "/tmp/attacker-writable-dir/ls -la /workspace" {
		t.Errorf("expected the planted binary unrecorded, got %+v", v.Unrecorded)
	}
}

// Sibling to TestE2E_T3_BareNameMasquerading: the same bare claim against a
// binary that really did resolve into a standard system directory still
// corroborates, so Fix 2 doesn't break the honest bare-name convention.
func TestE2E_BareNameAgainstTrustedPathIsNOTFaithful(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.ProcessExec, "ls -la /workspace", nil, nil),
	}
	ground := models.GroundTruth{
		ge(5, models.ProcessExec, "/usr/bin/ls -la /workspace", nil, nil),
	}

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Errorf("bare name vs /usr/bin path should be NOT FAITHFUL due to strict matching, got %+v", v)
	}
	if len(v.Corroborated) != 0 {
		t.Errorf("expected 0 corroborated, got %d", len(v.Corroborated))
	}
	if len(v.Unwitnessed) != 1 || len(v.Unrecorded) != 1 {
		t.Errorf("expected 1 unwitnessed and 1 unrecorded, got U=%d R=%d", len(v.Unwitnessed), len(v.Unrecorded))
	}
}

// Combined attack: omission + fabrication + substitution in the same trajectory.
func TestE2E_CombinedAttack(t *testing.T) {
	traj, ground := honestTrajectory()

	// T1: drop the network request (index 2)
	traj = append(traj[:2], traj[3:]...)

	// T2: insert a fabricated entry
	fake := te(2500, models.FileRead, "/workspace/README.md", nil, sp("readme_h"))
	traj = append(traj[:2], append(models.Trajectory{fake}, traj[2:]...)...)

	// T3: substitute the file write hash (now at index 3 after mutations)
	traj[3].OutputHash = sp("tampered_hash")

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("combined attack should be NOT FAITHFUL")
	}
	if len(v.Unrecorded) != 1 {
		t.Errorf("expected 1 unrecorded (omitted net request), got %d", len(v.Unrecorded))
	}
	if len(v.Unwitnessed) != 1 {
		t.Errorf("expected 1 unwitnessed (fabricated README read), got %d", len(v.Unwitnessed))
	}
	if len(v.Mismatched) != 1 {
		t.Errorf("expected 1 mismatched (substituted file write), got %d", len(v.Mismatched))
	}
}

// Fix 4 combined scenario: an omission (T1), a fabrication (T2), and two
// check opt-outs in the same trajectory -- a FileClose with no OutputHash
// and a ProcessExit with no ExitCode, both against ground truth that did
// capture those values. All four must surface; none may launder into
// Corroborated.
func TestE2E_CombinedAttackWithOmittedEvidence(t *testing.T) {
	traj := models.Trajectory{
		te(0, models.FileRead, "/workspace/config.yaml", nil, sp("cfg_h")),
		te(1000, models.NetRequest, "https://api.openai.com/v1/chat", sp("req_h"), sp("resp_h")),
		te(2000, models.FileClose, "/workspace/output.txt", nil, nil),
		{Timestamp: baseTime.Add(3000 * time.Millisecond), ActionType: models.ProcessExit,
			Target: "/usr/bin/git push"},
	}
	ground := models.GroundTruth{
		ge(2, models.FileRead, "/workspace/config.yaml", nil, sp("cfg_h")),
		ge(1003, models.NetRequest, "https://api.openai.com/v1/chat", sp("req_h"), sp("resp_h")),
		ge(2001, models.FileClose, "/workspace/output.txt", nil, sp("real_out_h")),
		{IsTopLevel: bp(true), Timestamp: baseTime.Add(3004 * time.Millisecond),
			ActionType: models.ProcessExit, Target: "/usr/bin/git push", ExitCode: ip(128)},
		ge(4000, models.FileRead, "/workspace/secret.env", nil, sp("secret_h")),
	}

	// T2: agent fabricates a benign read that never happened.
	traj = append(traj, te(3500, models.FileRead, "/workspace/README.md", nil, sp("readme_h")))

	v := Verify(traj, ground, cfg)

	if v.Faithful {
		t.Error("combined attack should be NOT FAITHFUL")
	}
	if len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != "/workspace/secret.env" {
		t.Errorf("expected 1 unrecorded (omitted secret read), got %+v", v.Unrecorded)
	}
	if len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != "/workspace/README.md" {
		t.Errorf("expected 1 unwitnessed (fabricated README read), got %+v", v.Unwitnessed)
	}
	if len(v.Mismatched) != 2 {
		t.Errorf("expected 2 mismatched (omitted OutputHash + omitted ExitCode), got %d",
			len(v.Mismatched))
	}
	if len(v.Corroborated) != 2 {
		t.Errorf("expected 2 corroborated (config read + net request), got %d",
			len(v.Corroborated))
	}
}

// Listener events are capability evidence (09 item 2): observed, counted,
// never aligned. An honest agent's trajectory cannot mention them, so they
// must not read as Unrecorded and must not make the run unfaithful, whether
// or not the probe set a level on the event.
func TestVerify_ListenersAreCapabilityNotUnrecorded(t *testing.T) {
	now := time.Now()
	top := true
	g := models.GroundTruth{
		{Timestamp: now, ActionType: models.NetBind, Target: "0.0.0.0:8080"},
		{Timestamp: now, ActionType: models.NetListen, Target: "0.0.0.0:8080", IsTopLevel: &top},
		{Timestamp: now, ActionType: models.NetUnixConnect, Target: "unix:/var/run/docker.sock"},
		{Timestamp: now, ActionType: models.ProcessExec, Target: "ls"},
	}
	tr := models.Trajectory{{Timestamp: now, ActionType: models.ProcessExec, Target: "ls"}}
	v := Verify(tr, g, matching.Config{Delta: time.Second})
	if !v.Faithful {
		t.Errorf("Faithful = false, want true: unrecorded=%v unwitnessed=%v", v.Unrecorded, v.Unwitnessed)
	}
	if len(v.Unrecorded) != 0 {
		t.Errorf("listeners reported as Unrecorded: %v", v.Unrecorded)
	}
	if len(v.Capability) != 3 {
		t.Errorf("Capability = %d events, want 3", len(v.Capability))
	}
	if len(v.Corroborated) != 1 {
		t.Errorf("Corroborated = %d, want 1: the exec must still align", len(v.Corroborated))
	}
}

// A claim of an unclaimable type can only come from a hand-built trajectory
// (ParseTrajectory rejects it). If one reaches Verify it must still not
// corroborate against an observed listener, or an agent could launder a
// listener into a corroborated action.
func TestVerify_ListenerClaimNeverCorroborates(t *testing.T) {
	now := time.Now()
	g := models.GroundTruth{{Timestamp: now, ActionType: models.NetListen, Target: "0.0.0.0:8080"}}
	tr := models.Trajectory{{Timestamp: now, ActionType: models.NetListen, Target: "0.0.0.0:8080"}}
	v := Verify(tr, g, matching.Config{Delta: time.Second})
	if len(v.Corroborated) != 0 {
		t.Errorf("a listener claim corroborated: %v", v.Corroborated)
	}
	if len(v.Unwitnessed) != 1 {
		t.Errorf("Unwitnessed = %d, want the claim reported", len(v.Unwitnessed))
	}
	if v.Faithful {
		t.Error("a claim that no valid trajectory can make must not yield FAITHFUL")
	}
}
