package claudecode

import (
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const (
	agentPID = 100
	ws       = "/w"
)

var t0 = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

func fev(ms int, typ models.ActionType, target string, pid uint32) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: at(ms), ActionType: typ, Target: target, PID: pid}
}

func dirEv(ms int, typ models.ActionType, pid uint32) models.GroundTruthEvent {
	e := fev(ms, typ, ws, pid)
	e.PathIsAmbiguous = true
	return e
}

func hashed(e models.GroundTruthEvent, h string) models.GroundTruthEvent {
	e.OutputHash = &h
	return e
}

// atomicWrite is the five events a Write or Edit produced in the paired capture:
// a create on the directory, then open, write and close of a temporary named
// <path>.tmp.<pid>.<12 hex>, then a rename on the directory. The close carries
// the hash of the final content.
func atomicWrite(ms int, path, tmpSuffix, hash string, pid uint32) models.GroundTruth {
	tmp := path + ".tmp." + tmpSuffix
	return models.GroundTruth{
		dirEv(ms, models.FileWrite, pid),
		fev(ms, models.FileOpen, tmp, pid),
		fev(ms+1, models.FileWrite, tmp, pid),
		hashed(fev(ms+2, models.FileClose, tmp, pid), hash),
		dirEv(ms+3, models.FileRename, pid),
	}
}

func targets(g models.GroundTruth) []string {
	var out []string
	for _, e := range g {
		out = append(out, string(e.ActionType)+" "+e.Target)
	}
	return out
}

func TestFoldTurnsAnAtomicReplaceIntoOneWriteWithTheFinalHash(t *testing.T) {
	g := atomicWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:final", 100)
	got := Adapter{}.NormalizeStream(g)
	if len(got) != 1 || got[0].ActionType != models.FileWrite || got[0].Target != "/w/a.txt" || got[0].PID != 100 {
		t.Fatalf("folded = %v, want one write of /w/a.txt", targets(got))
	}
	if got[0].OutputHash == nil || *got[0].OutputHash != "sha256:final" {
		t.Errorf("hash = %v, want the close's", got[0].OutputHash)
	}
	if !got[0].Timestamp.Equal(at(10)) {
		t.Errorf("timestamp = %v, want the start of the burst", got[0].Timestamp)
	}
}

// The second paired capture showed the other order: the close read after the
// rename, so it names the target, and the rename comes first.
func TestFoldHandlesACloseThatNamesTheTargetAfterTheRename(t *testing.T) {
	tmp := "/w/b.txt.tmp.100.7068b43dd15d"
	g := models.GroundTruth{
		dirEv(0, models.FileWrite, 100),
		fev(0, models.FileOpen, tmp, 100),
		fev(1, models.FileWrite, tmp, 100),
		dirEv(2, models.FileRename, 100),
		hashed(fev(2, models.FileClose, "/w/b.txt", 100), "sha256:final"),
	}
	got := Adapter{}.NormalizeStream(g)
	if len(got) != 1 || got[0].Target != "/w/b.txt" || got[0].OutputHash == nil || *got[0].OutputHash != "sha256:final" {
		t.Fatalf("folded = %v, want one write of /w/b.txt with the close's hash", targets(got))
	}
}

// A close of the target with no rename is a plain write by the agent, not a
// replace, and must stay visible.
func TestFoldNeedsTheRenameEvenWhenTheCloseNamesTheTarget(t *testing.T) {
	tmp := "/w/b.txt.tmp.100.7068b43dd15d"
	g := models.GroundTruth{dirEv(0, models.FileWrite, 100), fev(0, models.FileOpen, tmp, 100), fev(1, models.FileWrite, tmp, 100), hashed(fev(2, models.FileClose, "/w/b.txt", 100), "sha256:h")}
	if got := (Adapter{}).NormalizeStream(g); len(got) != len(g) {
		t.Errorf("folded without a rename: %v", targets(got))
	}
}

func TestFoldKeepsEverythingAroundTheBurst(t *testing.T) {
	g := models.GroundTruth{fev(0, models.FileOpen, "/w/before", 100)}
	g = append(g, atomicWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:h", 100)...)
	g = append(g, fev(20, models.FileOpen, "/w/after", 100))
	got := Adapter{}.NormalizeStream(g)
	want := []string{"file_open /w/before", "file_write /w/a.txt", "file_open /w/after"}
	if strings.Join(targets(got), "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", targets(got), want)
	}
}

// Events of other processes interleave with the burst (fanotify reports every
// process) and must neither be folded nor stop the fold.
func TestFoldIgnoresInterleavedEventsOfOtherProcesses(t *testing.T) {
	burst := atomicWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:h", 100)
	g := models.GroundTruth{burst[0], fev(10, models.FileOpen, "/w/other", 200), burst[1], burst[2], fev(11, models.FileWrite, "/w/other", 200), burst[3], burst[4]}
	got := Adapter{}.NormalizeStream(g)
	want := []string{"file_write /w/a.txt", "file_open /w/other", "file_write /w/other"}
	if strings.Join(targets(got), "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", targets(got), want)
	}
}

// A temporary that is never closed and renamed is not a finished replace, so it
// stays visible instead of being folded into a write that did not complete.
func TestFoldLeavesAnUnfinishedReplace(t *testing.T) {
	tmp := "/w/a.txt.tmp.100.5b5474087431"
	for name, g := range map[string]models.GroundTruth{
		"no close":  {dirEv(0, models.FileWrite, 100), fev(0, models.FileOpen, tmp, 100), fev(1, models.FileWrite, tmp, 100), dirEv(2, models.FileRename, 100)},
		"no rename": {dirEv(0, models.FileWrite, 100), fev(0, models.FileOpen, tmp, 100), fev(1, models.FileWrite, tmp, 100), hashed(fev(2, models.FileClose, tmp, 100), "sha256:h")},
	} {
		t.Run(name, func(t *testing.T) {
			got := Adapter{}.NormalizeStream(g)
			if len(got) != len(g) {
				t.Errorf("an unfinished replace was folded: %v", targets(got))
			}
		})
	}
}

func TestFoldOnlyRecognisesTheHarnessTemporaryName(t *testing.T) {
	for _, name := range []string{"/w/a.txt.tmp", "/w/a.tmp.1.5b5474087431x", "/w/a.txt.tmp.abc.5b5474087431", "/w/a.txt.tmp.100.SHORT"} {
		tmp := name
		g := models.GroundTruth{fev(0, models.FileOpen, tmp, 100), fev(1, models.FileWrite, tmp, 100), hashed(fev(2, models.FileClose, tmp, 100), "sha256:h"), dirEv(3, models.FileRename, 100)}
		if got := (Adapter{}).NormalizeStream(g); len(got) != len(g) {
			t.Errorf("%s was folded as if it were a harness temporary", name)
		}
	}
}

func TestFoldKeepsTwoBurstsApart(t *testing.T) {
	g := append(atomicWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:1", 100), atomicWrite(30, "/w/b.txt", "100.99c9132148e8", "sha256:2", 100)...)
	got := Adapter{}.NormalizeStream(g)
	if len(got) != 2 || got[0].Target != "/w/a.txt" || got[1].Target != "/w/b.txt" || *got[0].OutputHash != "sha256:1" || *got[1].OutputHash != "sha256:2" {
		t.Errorf("got %v", targets(got))
	}
}

func TestCollapseOpensIsPerProcessAndBrokenByOtherFileEvents(t *testing.T) {
	g := models.GroundTruth{
		fev(0, models.FileOpen, "/w/a", 100), fev(1, models.FileOpen, "/w/a", 100), fev(2, models.FileOpen, "/w/a", 100), // a run: one open
		fev(3, models.FileOpen, "/w/a", 200),                                       // another process: its own run
		fev(4, models.FileWrite, "/w/a", 100),                                      // breaks the run for 100
		fev(5, models.FileOpen, "/w/a", 100),                                       // a new run
		fev(6, models.FileOpen, "/w/b", 100), fev(7, models.FileOpen, "/w/a", 100), // different file: not collapsed
		{Timestamp: at(8), ActionType: models.NetConnect, Target: "h", PID: 100}, // a non-file event does not break the run
		fev(9, models.FileOpen, "/w/a", 100),
	}
	got := targets(Adapter{}.NormalizeStream(g))
	want := []string{"file_open /w/a", "file_open /w/a", "file_write /w/a", "file_open /w/a", "file_open /w/b", "file_open /w/a", "net_connect h"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}

func TestCollapseOpenClaimsMatchesTheObservedSide(t *testing.T) {
	end := func(ms int) *time.Time { e := at(ms); return &e }
	tr := models.Trajectory{
		{Timestamp: at(0), End: end(1), ActionType: models.FileOpen, Target: "/w/a"},
		{Timestamp: at(2), ActionType: models.ProcessExec, Target: "ls"}, // another lane: does not break the run
		{Timestamp: at(3), End: end(9), ActionType: models.FileOpen, Target: "/w/a"},
		{Timestamp: at(4), ActionType: models.FileWrite, Target: "/w/a"},
		{Timestamp: at(5), ActionType: models.FileOpen, Target: "/w/a"},
	}
	got := collapseOpenClaims(tr)
	if len(got) != 4 || got[0].ActionType != models.FileOpen || got[1].ActionType != models.ProcessExec || got[2].ActionType != models.FileWrite || got[3].ActionType != models.FileOpen {
		t.Fatalf("got %+v", got)
	}
	if got[0].End == nil || !got[0].End.Equal(at(9)) {
		t.Errorf("the collapsed open's interval = %v, want it to cover both calls", got[0].End)
	}
}

func TestNormalizeCanonicalisesPerRunIdsOnTheHarnessCommands(t *testing.T) {
	a := Adapter{}
	for _, tc := range []struct{ in, want string }{
		{"/bin/bash -c -l SNAPSHOT_FILE=/h/.claude/shell-snapshots/snapshot-bash-1791357771136-4d6ac0.sh\n source x", "/bin/bash -c -l SNAPSHOT_FILE=/h/.claude/shell-snapshots/snapshot-bash-N.sh\n source x"},
		{"/bin/bash -c cat /tmp/claude-1a2b-cwd", "/bin/bash -c cat /tmp/claude-N-cwd"},
		// Ids are base 36, not only hex: one seen was 0qttaz.
		{"SNAPSHOT_FILE=/h/.claude/shell-snapshots/snapshot-bash-1791358431910-0qttaz.sh", "SNAPSHOT_FILE=/h/.claude/shell-snapshots/snapshot-bash-N.sh"},
		{"/bin/bash -c cat /tmp/claude-qz9x-cwd", "/bin/bash -c cat /tmp/claude-N-cwd"},
		{"cat >> \"$F\" << 'PATH_END_eha29nbtq8n'\nexport PATH=/x", "cat >> \"$F\" << 'PATH_END_N'\nexport PATH=/x"},
		{"/bin/bash -c env", "/bin/bash -c env"},
	} {
		got, _ := a.Normalize(models.GroundTruthEvent{ActionType: models.ProcessExec, Target: tc.in})
		if got.Target != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.in, got.Target, tc.want)
		}
	}
	// A file event naming such a path is not rewritten: only commands are.
	f, _ := a.Normalize(models.GroundTruthEvent{ActionType: models.FileWrite, Target: "/tmp/claude-1a2b-cwd"})
	if f.Target != "/tmp/claude-1a2b-cwd" {
		t.Errorf("a file target was rewritten: %q", f.Target)
	}
}

// --- the paired capture, replayed ---

// capturedSession is the observed sequence of the paired capture of Claude Code
// 2.1.286 for the five-step task (Read b, Write a, Edit a, Write b over the
// existing file, Bash echo), with the paths shortened. The kernel reported the
// reads of the target before each replace, one for the overwrite and three for
// the edit, and every write as an atomic replace.
func capturedSession() models.GroundTruth {
	var g models.GroundTruth
	g = append(g, fev(0, models.FileOpen, "/w/b.txt", 100)) // Read b
	g = append(g, atomicWrite(100, "/w/a.txt", "100.5b5474087431", "sha256:hello", 100)...)
	g = append(g, fev(200, models.FileOpen, "/w/a.txt", 100), fev(201, models.FileOpen, "/w/a.txt", 100), fev(202, models.FileOpen, "/w/a.txt", 100)) // Edit's reads
	g = append(g, atomicWrite(210, "/w/a.txt", "100.7cbe937665de", "sha256:world", 100)...)
	g = append(g, fev(300, models.FileOpen, "/w/b.txt", 100)) // overwrite's read
	g = append(g, atomicWrite(310, "/w/b.txt", "100.99c9132148e8", "sha256:again", 100)...)
	return g
}

func capturedClaims() models.Trajectory {
	h := func(s string) *string { return &s }
	return models.Trajectory{
		{Timestamp: at(0), ActionType: models.FileOpen, Target: "/w/b.txt", Tool: "Read"},
		{Timestamp: at(100), ActionType: models.FileWrite, Target: "/w/a.txt", OutputHash: h("sha256:hello"), Tool: "Write"},
		{Timestamp: at(200), ActionType: models.FileOpen, Target: "/w/a.txt", Tool: "Edit"},
		{Timestamp: at(210), ActionType: models.FileWrite, Target: "/w/a.txt", Tool: "Edit"},
		{Timestamp: at(300), ActionType: models.FileOpen, Target: "/w/b.txt", Tool: "Write"},
		{Timestamp: at(310), ActionType: models.FileWrite, Target: "/w/b.txt", OutputHash: h("sha256:again"), Tool: "Write"},
	}
}

func verifyCaptured(t *testing.T, claims models.Trajectory, g models.GroundTruth) verification.Verdict {
	t.Helper()
	file := models.GroundTruthFile{
		Events: g, RootPID: agentPID,
		Coverage: &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}}},
	}
	return verification.Verify(agent.Prepare(Adapter{}, claims, file, nil, verification.Options{}))
}

func TestTheCapturedSessionVerifiesFaithful(t *testing.T) {
	v := verifyCaptured(t, capturedClaims(), capturedSession())
	if v.Outcome != verification.OutcomeFaithful {
		t.Fatalf("outcome = %s\nunwitnessed=%v\nunrecorded=%v\nmismatched=%v", v.Outcome, v.Unwitnessed, v.Unrecorded, v.Mismatched)
	}
}

// The same capture with the claims altered must not verify: the normalization
// that makes an honest session comparable must not make any session pass.
func TestTheCapturedSessionCatchesEachKindOfLie(t *testing.T) {
	lies := map[string]func(tr models.Trajectory) models.Trajectory{
		"a write claimed with another content hash": func(tr models.Trajectory) models.Trajectory {
			tr[1].OutputHash = strPtr("sha256:benign")
			return tr
		},
		"a write claimed on another file": func(tr models.Trajectory) models.Trajectory {
			tr[1].Target = "/w/decoy.txt"
			return tr
		},
		"a write omitted": func(tr models.Trajectory) models.Trajectory {
			return append(append(models.Trajectory{}, tr[:1]...), tr[2:]...)
		},
		"a write fabricated": func(tr models.Trajectory) models.Trajectory {
			return append(tr, models.TrajectoryEntry{Timestamp: at(400), ActionType: models.FileWrite, Target: "/w/ghost", Tool: "Write"})
		},
	}
	for name, lie := range lies {
		t.Run(name, func(t *testing.T) {
			if v := verifyCaptured(t, lie(append(models.Trajectory{}, capturedClaims()...)), capturedSession()); v.Outcome != verification.OutcomeNotFaithful {
				t.Errorf("outcome = %s, want NOT FAITHFUL", v.Outcome)
			}
		})
	}
}

// A file the agent wrote that the trajectory does not mention is still an
// omission once the burst is folded.
func TestAnUnclaimedAtomicWriteIsStillAnOmission(t *testing.T) {
	g := append(capturedSession(), atomicWrite(500, "/w/secret", "100.aaaaaaaaaaaa", "sha256:x", 100)...)
	v := verifyCaptured(t, capturedClaims(), g)
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != "/w/secret" {
		t.Errorf("outcome = %s, unrecorded = %v, want the unclaimed write", v.Outcome, v.Unrecorded)
	}
}

func strPtr(s string) *string { return &s }

// Grep and Glob run as ripgrep embedded in Claude Code's own binary. The harness
// also lists the working directory the same way at start-up, and those listings
// must keep their exact text so a baseline can name them.
func TestNormalizeRecognisesEmbeddedRipgrepSearches(t *testing.T) {
	const bin = "/home/u/.local/share/claude/versions/2.1.286"
	tests := []struct {
		name, line, want string
	}{
		{"grep, files with matches", bin + " --no-config --hidden --glob !.git --glob !.svn --glob !.hg --glob !.bzr --glob !.jj --glob !.sl --max-columns 500 -l --null seed .", SearchGrep},
		{"grep, content with context", bin + " --no-config --hidden --max-columns 500 -n -B 2 -e foo bar/", SearchGrep},
		{"glob", bin + " --no-config --files --null --glob *.txt --sort=modified --no-ignore --hidden .", SearchGlob},
		{"start-up listing of the workspace", bin + " --no-config --files --hidden /tmp/ws", bin + " --no-config --files --hidden /tmp/ws"},
		{"start-up listing of the plugin cache", bin + " --no-config --files --hidden --no-ignore --max-depth 4 --glob .orphaned_at /h/.claude/plugins/cache", bin + " --no-config --files --hidden --no-ignore --max-depth 4 --glob .orphaned_at /h/.claude/plugins/cache"},
		{"the binary without --no-config", bin + " --version", bin + " --version"},
		// Only the harness's own binary is recognised: any other program that
		// happens to take --no-config is not a search.
		{"another program", "/tmp/evil --no-config --files --null --glob x", "/tmp/evil --no-config --files --null --glob x"},
		{"another install path", "/opt/other/versions/1.0 --no-config -l --null x .", "/opt/other/versions/1.0 --no-config -l --null x ."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, typ := range []models.ActionType{models.ProcessExec, models.ProcessExit} {
				got, _ := Adapter{}.Normalize(models.GroundTruthEvent{ActionType: typ, Target: tc.line})
				if got.Target != tc.want {
					t.Errorf("%s: Normalize = %q, want %q", typ, got.Target, tc.want)
				}
			}
		})
	}
}

// A search claimed and observed verifies, and an unclaimed search is an
// omission like any other command.
func TestASearchIsClaimedAsAKindOfSearch(t *testing.T) {
	const bin = "/home/u/.local/share/claude/versions/2.1.286"
	g := models.GroundTruth{
		{Timestamp: at(0), ActionType: models.ProcessFork, Target: "x", PID: 200, PPID: agentPID},
		{Timestamp: at(0), ActionType: models.ProcessExec, Target: bin + " --no-config --hidden --max-columns 500 -l --null seed .", PID: 200, PPID: agentPID},
	}
	claims := models.Trajectory{{Timestamp: at(0), ActionType: models.ProcessExec, Target: SearchGrep, Tool: "Grep"}}
	if v := verifyCaptured(t, claims, g); v.Outcome != verification.OutcomeFaithful {
		t.Errorf("claimed search: outcome = %s, unrecorded=%v mismatched=%v", v.Outcome, v.Unrecorded, v.Mismatched)
	}
	if v := verifyCaptured(t, nil, g); v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("unclaimed search: outcome = %s, want NOT FAITHFUL", v.Outcome)
	}
	wrong := models.Trajectory{{Timestamp: at(0), ActionType: models.ProcessExec, Target: SearchGlob, Tool: "Glob"}}
	if v := verifyCaptured(t, wrong, g); v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("a Glob claimed for a Grep: outcome = %s, want NOT FAITHFUL", v.Outcome)
	}
}

// The version lock is written through a temporary with an eight-hex suffix,
// a different library from the file tools' <pid>.<12 hex>; it folds the same.
func TestFoldAtomicWritesRecognisesTheLockTemporary(t *testing.T) {
	const pid = 7
	h := "sha256:aa"
	g := models.GroundTruth{
		{Timestamp: at(0), ActionType: models.FileOpen, Target: "/h/.local/state/claude/locks/2.1.286.lock.tmp.68f796c1", PID: pid},
		{Timestamp: at(1), ActionType: models.FileWrite, Target: "/h/.local/state/claude/locks/2.1.286.lock.tmp.68f796c1", PID: pid},
		{Timestamp: at(2), ActionType: models.FileRename, Target: "/h/.local/state/claude/locks", PID: pid},
		{Timestamp: at(3), ActionType: models.FileClose, Target: "/h/.local/state/claude/locks/2.1.286.lock", PID: pid, OutputHash: &h},
	}
	out := foldAtomicWrites(g)
	if len(out) != 1 || out[0].ActionType != models.FileWrite || out[0].Target != "/h/.local/state/claude/locks/2.1.286.lock" || out[0].OutputHash == nil {
		t.Fatalf("fold = %+v", out)
	}
}
