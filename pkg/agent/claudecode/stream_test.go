package claudecode

import (
	"encoding/json"
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

// The tools capture of 2.1.296 showed a third mix: the open read before the
// rename names the temporary, and the write and close read after it name the
// target, ahead of the rename (I-34). The write belongs to the replace.
func TestFoldTakesAWriteThatNamesTheTargetJustBeforeTheClose(t *testing.T) {
	tmp := "/w/notes.txt.tmp.100.3a597989445f"
	g := models.GroundTruth{
		dirEv(0, models.FileWrite, 100),
		fev(0, models.FileOpen, tmp, 100),
		fev(1, models.FileWrite, "/w/notes.txt", 100),
		hashed(fev(1, models.FileClose, "/w/notes.txt", 100), "sha256:final"),
		dirEv(1, models.FileRename, 100),
	}
	got := Adapter{}.NormalizeStream(g)
	if len(got) != 1 || got[0].Target != "/w/notes.txt" || got[0].OutputHash == nil || *got[0].OutputHash != "sha256:final" {
		t.Fatalf("folded = %v, want one write of /w/notes.txt with the close's hash", targets(got))
	}
}

// A write that names the target is taken only as the last events of the pid
// before a close of the target: one followed by another event of the pid, or
// one before a close that still names the temporary, is a write of its own.
func TestFoldLeavesAWriteOfTheTargetThatIsNotJustBeforeTheClose(t *testing.T) {
	tmp := "/w/notes.txt.tmp.100.3a597989445f"
	for _, c := range []struct {
		name string
		g    models.GroundTruth
		want []string
	}{
		{"another event between", models.GroundTruth{
			dirEv(0, models.FileWrite, 100),
			fev(0, models.FileOpen, tmp, 100),
			fev(1, models.FileWrite, "/w/notes.txt", 100),
			fev(1, models.FileOpen, "/w/x", 100),
			hashed(fev(2, models.FileClose, "/w/notes.txt", 100), "sha256:h"),
			dirEv(2, models.FileRename, 100),
		}, []string{"file_write /w/notes.txt", "file_write /w/notes.txt", "file_open /w/x"}},
		{"close names the temporary", models.GroundTruth{
			dirEv(0, models.FileWrite, 100),
			fev(0, models.FileOpen, tmp, 100),
			fev(1, models.FileWrite, "/w/notes.txt", 100),
			hashed(fev(2, models.FileClose, tmp, 100), "sha256:h"),
			dirEv(2, models.FileRename, 100),
		}, []string{"file_write /w/notes.txt", "file_write /w/notes.txt"}},
	} {
		got := Adapter{}.NormalizeStream(c.g)
		if strings.Join(targets(got), "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: got %v, want %v", c.name, targets(got), c.want)
		}
		// The folded write carries the close's hash; the write left alone has none.
		n := 0
		for _, e := range got {
			if e.ActionType == models.FileWrite && e.Target == "/w/notes.txt" && e.OutputHash == nil {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: %d unhashed writes of the target left, want 1: %v", c.name, n, targets(got))
		}
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

// The P-17 capture, recorded before P-18, holds a replace's one rename as two
// directory renames of the same pid, back to back: the kernel's unmerged
// halves, which the probe now drops at emission. Both belong to the replace
// (I-33).
func TestFoldTakesBothHalvesOfASplitRename(t *testing.T) {
	g := atomicWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:h", 100)
	g = append(g, dirEv(13, models.FileRename, 100), fev(20, models.FileOpen, "/w/after", 100))
	got := Adapter{}.NormalizeStream(g)
	want := []string{"file_write /w/a.txt", "file_open /w/after"}
	if strings.Join(targets(got), "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", targets(got), want)
	}
}

// Only the one rename a split can add is taken, under a condition narrower
// than P-18's: a third rename, a second one after another event of the pid,
// or one after another process's event on the directory stays.
func TestFoldTakesNoMoreThanTheSplitRename(t *testing.T) {
	otherDir := dirEv(13, models.FileRename, 100)
	otherDir.Target = "/v"
	for _, c := range []struct {
		name string
		tail models.GroundTruth
		want []string
	}{
		{"third rename", models.GroundTruth{dirEv(13, models.FileRename, 100), dirEv(14, models.FileRename, 100)},
			[]string{"file_write /w/a.txt", "file_rename /w"}},
		{"after another event", models.GroundTruth{fev(13, models.FileOpen, "/w/x", 100), dirEv(14, models.FileRename, 100)},
			[]string{"file_write /w/a.txt", "file_open /w/x", "file_rename /w"}},
		{"rename of another directory", models.GroundTruth{otherDir},
			[]string{"file_write /w/a.txt", "file_rename /v"}},
		{"another process on the directory between", models.GroundTruth{dirEv(13, models.FileWrite, 200), dirEv(14, models.FileRename, 100)},
			[]string{"file_write /w/a.txt", "file_write /w", "file_rename /w"}},
	} {
		g := append(atomicWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:h", 100), c.tail...)
		if got := (Adapter{}).NormalizeStream(g); strings.Join(targets(got), "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: got %v, want %v", c.name, targets(got), c.want)
		}
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
	// A file event naming the cwd file keeps its id for pairing and is
	// rewritten where runs are compared (I-29, I-41): the harness opens it at
	// level 0 after each Bash call.
	raw := models.GroundTruthEvent{ActionType: models.FileWrite, Target: "/tmp/claude-1a2b-cwd"}
	if f, _ := a.Normalize(raw); f.Target != raw.Target {
		t.Errorf("Normalize rewrote the cwd file: %q", f.Target)
	}
	if f := a.Canonical(raw); f.Target != "/tmp/claude-N-cwd" {
		t.Errorf("the cwd file was not canonicalised: %q", f.Target)
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

// The two shapes the `tools` captures of 2.1.296 showed for the read that
// precedes a replace (I-39). In the first, the NotebookEdit's read merged into
// its read-after-rename batch as an ambiguous open of the directory, and the
// overwriting Write's read was a separate named open; in the second, the
// NotebookEdit's two reads were named and its replace used the temporary,
// and the Write's read merged into its batch. A NotebookEdit and an
// overwriting Write each claim an open and a write, and both shapes verify.
// A replace with no read, a create, leaves the claimed open unwitnessed.
func TestTheReadBeforeAReplaceVerifiesInBothCapturedShapes(t *testing.T) {
	const pid = agentPID
	nb, rep := "/w/analysis.ipynb", "/w/report.txt"
	nbHash, repHash := contentHash("nb-after"), contentHash("final")
	use := func(name string, input string) toolUse {
		return toolUse{id: name, name: name, input: json.RawMessage(input)}
	}
	var claims models.Trajectory
	for _, c := range []struct {
		u   toolUse
		res toolResult
		ms  int
	}{
		{use(toolNotebookEdit, `{"notebook_path":"`+nb+`"}`), toolResult{notebook: &notebookResult{path: nb, updated: "nb-after"}}, 0},
		{use(toolWrite, `{"file_path":"`+rep+`","content":"final"}`), toolResult{kind: "update"}, 100},
	} {
		entries, why := claimsFor(c.u, models.TrajectoryEntry{Timestamp: at(c.ms), Tool: c.u.name}, c.res)
		if why != "" {
			t.Fatalf("%s: %s", c.u.name, why)
		}
		claims = append(claims, entries...)
	}

	amb := func(ms int, typ models.ActionType) models.GroundTruthEvent { return dirEv(ms, typ, pid) }
	readAfterRename := func(ms int, path, hash string, read bool) models.GroundTruth {
		var g models.GroundTruth
		if read {
			g = append(g, amb(ms, models.FileOpen))
		}
		return append(g, amb(ms, models.FileWrite), amb(ms, models.FileRename),
			fev(ms, models.FileOpen, path, pid), fev(ms, models.FileWrite, path, pid), hashed(fev(ms, models.FileClose, path, pid), hash))
	}
	first := append(readAfterRename(0, nb, nbHash, true), fev(100, models.FileOpen, rep, pid))
	first = append(first, readAfterRename(101, rep, repHash, false)...)
	second := models.GroundTruth{fev(0, models.FileOpen, nb, pid), fev(1, models.FileOpen, nb, pid)}
	second = append(second, atomicWrite(2, nb, "100.a5e8eefa3361", nbHash, pid)...)
	second = append(second, readAfterRename(100, rep, repHash, true)...)

	for name, g := range map[string]models.GroundTruth{"first capture": first, "second capture": second} {
		t.Run(name, func(t *testing.T) {
			v := verifyCaptured(t, claims, g)
			if v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 4 {
				t.Errorf("outcome = %s, corroborated = %d\nunwitnessed=%v\nunrecorded=%v\nmismatched=%v", v.Outcome, len(v.Corroborated), v.Unwitnessed, v.Unrecorded, v.Mismatched)
			}
		})
	}
	t.Run("no read observed", func(t *testing.T) {
		g := append(readAfterRename(0, nb, nbHash, false), fev(100, models.FileOpen, rep, pid))
		g = append(g, readAfterRename(101, rep, repHash, false)...)
		v := verifyCaptured(t, claims, g)
		if v.Outcome != verification.OutcomeNotFaithful || len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != nb {
			t.Errorf("outcome = %s, unwitnessed = %v, want the notebook's open", v.Outcome, v.Unwitnessed)
		}
	})
}

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
	// The fold sees the raw suffix: the per-run ids are replaced only where
	// runs are compared (I-41), so a file literally named .tmp.N is no
	// temporary.
	for _, tmp := range []string{"/h/.local/state/claude/locks/2.1.286.lock.tmp.68f796c1", "/h/.local/state/claude/locks/2.1.286.lock.tmp.N"} {
		folds := !strings.HasSuffix(tmp, ".N")
		g := models.GroundTruth{
			{Timestamp: at(0), ActionType: models.FileOpen, Target: tmp, PID: pid},
			{Timestamp: at(1), ActionType: models.FileWrite, Target: tmp, PID: pid},
			{Timestamp: at(2), ActionType: models.FileRename, Target: "/h/.local/state/claude/locks", PID: pid},
			{Timestamp: at(3), ActionType: models.FileClose, Target: "/h/.local/state/claude/locks/2.1.286.lock", PID: pid, OutputHash: &h},
		}
		out := foldAtomicWrites(g)
		folded := len(out) == 1 && out[0].ActionType == models.FileWrite && out[0].Target == "/h/.local/state/claude/locks/2.1.286.lock" && out[0].OutputHash != nil
		if folded != folds {
			t.Fatalf("%s: fold = %+v, want folded %v", tmp, out, folds)
		}
	}
}

// The read-after-rename shape, as a capture of 2.1.286 on 2026-10-11 showed
// it: the directory's create and rename merged ahead of the file's open,
// write and close, every one naming the target (I-32). It folds into one
// write of the target with the close's hash; a direct write with no directory
// events around it is left alone.
func TestFoldAtomicWritesReadAfterTheRename(t *testing.T) {
	const pid = 553142
	h := "sha256:f08d"
	amb := func(ms int, typ models.ActionType) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at(ms), ActionType: typ, Target: "/ws", PID: pid, PathIsAmbiguous: true}
	}
	g := models.GroundTruth{
		amb(0, models.FileWrite),
		amb(0, models.FileRename),
		amb(0, models.FileOpen), // the directory's fsync, after the create and the rename
		{Timestamp: at(0), ActionType: models.FileOpen, Target: "/ws/notes.txt", PID: pid},
		{Timestamp: at(0), ActionType: models.FileWrite, Target: "/ws/notes.txt", PID: pid},
		{Timestamp: at(0), ActionType: models.FileClose, Target: "/ws/notes.txt", PID: pid, OutputHash: &h},
		// a plain in-place write later: no fold
		{Timestamp: at(10), ActionType: models.FileOpen, Target: "/ws/other.txt", PID: pid},
		{Timestamp: at(11), ActionType: models.FileWrite, Target: "/ws/other.txt", PID: pid},
		{Timestamp: at(12), ActionType: models.FileClose, Target: "/ws/other.txt", PID: pid, OutputHash: &h},
	}
	out := foldAtomicWrites(g)
	if len(out) != 4 || out[0].ActionType != models.FileWrite || out[0].Target != "/ws/notes.txt" || out[0].OutputHash == nil || *out[0].OutputHash != h {
		t.Fatalf("fold = %+v", out)
	}
	for _, e := range out[1:] {
		if e.Target != "/ws/other.txt" {
			t.Errorf("the in-place write was touched: %+v", out)
		}
	}
}

// The batch of a read-after-rename replace of an existing file, as the
// `tools` captures of 2.1.296 showed it (2026-10-12): an ambiguous open of
// the directory first, then its create and rename, then open, write and close
// of the target. The open is the harness's read of the file it replaces,
// whose inode the rename unlinked before the batch was read (I-39). It
// becomes an open of the target with no input hash, ahead of the write; a
// replace that created its file has no such open, and an open of the
// directory by another process, or after the create, is not taken as one.
func TestFoldTurnsTheMergedReadOfAReplacedFileIntoAnOpen(t *testing.T) {
	const pid = 1185855
	h := "sha256:2443630"
	amb := func(typ models.ActionType, p uint32) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at(0), ActionType: typ, Target: "/ws", PID: p, PathIsAmbiguous: true}
	}
	file := func(typ models.ActionType) models.GroundTruthEvent {
		e := models.GroundTruthEvent{Timestamp: at(0), ActionType: typ, Target: "/ws/report.txt", PID: pid}
		if typ == models.FileClose {
			e.OutputHash = &h
		}
		if typ == models.FileOpen {
			e.InputHash = strPtr("sha256:7743ce3") // the probe's hash of the new inode, not the read one
		}
		return e
	}
	tail := models.GroundTruth{amb(models.FileWrite, pid), amb(models.FileRename, pid), file(models.FileOpen), file(models.FileWrite), file(models.FileClose)}
	for name, tc := range map[string]struct {
		head models.GroundTruth
		mid  models.GroundTruth // between the create and the rename
		want []string
	}{
		"the read merged into the batch": {
			head: models.GroundTruth{amb(models.FileOpen, pid)},
			want: []string{"file_open /ws/report.txt", "file_write /ws/report.txt"},
		},
		"a replace that created its file": {
			want: []string{"file_write /ws/report.txt"},
		},
		"an open of the directory by another process": {
			head: models.GroundTruth{amb(models.FileOpen, 7)},
			want: []string{"file_open /ws", "file_write /ws/report.txt"},
		},
		"an open of the directory after the create": {
			mid:  models.GroundTruth{amb(models.FileOpen, pid)},
			want: []string{"file_write /ws/report.txt"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := append(models.GroundTruth{}, tc.head...)
			g = append(g, tail[0])
			g = append(g, tc.mid...)
			g = append(g, tail[1:]...)
			out := foldAtomicWrites(g)
			if got := targets(out); strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("fold = %v, want %v", got, tc.want)
			}
			w := out[len(out)-1]
			if w.OutputHash == nil || *w.OutputHash != h {
				t.Errorf("write = %+v, want the close's hash", w)
			}
			if o := out[0]; o.Target == "/ws/report.txt" && o.ActionType == models.FileOpen && (o.InputHash != nil || o.PID != pid || o.PathIsAmbiguous) {
				t.Errorf("open = %+v, want the agent's open with no input hash", o)
			}
		})
	}
}

// An Edit reads its file one or more times by name and then, in the
// read-after-rename shape, once more inside the batch (the edits fixture and
// the second tools capture). The open the fold makes from the merged read is
// adjacent to the named ones and collapses with them, so the Edit still shows
// one open carrying the first open's input hash.
func TestTheMergedReadOfAnEditCollapsesWithItsNamedReads(t *testing.T) {
	const pid = 9
	in, h := "sha256:eb87ce4", "sha256:a5eeda1"
	ev := func(ms int, typ models.ActionType, target string, amb bool) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at(ms), ActionType: typ, Target: target, PID: pid, PathIsAmbiguous: amb}
	}
	named := ev(0, models.FileOpen, "/ws/notes.txt", false)
	named.InputHash = &in
	closed := ev(10, models.FileClose, "/ws/notes.txt", false)
	closed.OutputHash = &h
	g := models.GroundTruth{
		named, named,
		ev(5, models.FileOpen, "/home/u/.claude/plugins/installed_plugins.json", false),
		named,
		ev(10, models.FileOpen, "/ws", true),
		ev(10, models.FileWrite, "/ws", true),
		ev(10, models.FileRename, "/ws", true),
		ev(10, models.FileOpen, "/ws/notes.txt", false),
		ev(10, models.FileWrite, "/ws/notes.txt", false),
		closed,
	}
	out := Adapter{}.NormalizeStream(g)
	want := []string{"file_open /ws/notes.txt", "file_open /home/u/.claude/plugins/installed_plugins.json", "file_write /ws/notes.txt"}
	if got := targets(out); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v, want %v", got, want)
	}
	if out[0].InputHash == nil || *out[0].InputHash != in {
		t.Errorf("open = %+v, want the first named open's input hash", out[0])
	}
}

// The harness reads its own files between the opens a tool makes (a plugin
// list between an Edit's two pre-check opens, in a capture of 2026-10-11).
// Those events do not break a run of opens; a tool's own write does.
func TestCollapseOpensIgnoresTheHarnessOwnFiles(t *testing.T) {
	const pid = 9
	ev := func(ms int, typ models.ActionType, target string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at(ms), ActionType: typ, Target: target, PID: pid}
	}
	g := models.GroundTruth{
		ev(0, models.FileOpen, "/ws/notes.txt"),
		ev(1, models.FileOpen, "/home/u/.claude/plugins/installed_plugins.json"),
		ev(2, models.FileOpen, "/ws/notes.txt"), // collapsed: only a harness read between
		ev(3, models.FileWrite, "/ws/notes.txt"),
		ev(4, models.FileOpen, "/ws/notes.txt"), // kept: a write between
	}
	out := collapseOpens(g)
	var got []string
	for _, e := range out {
		got = append(got, string(e.ActionType)+" "+e.Target)
	}
	want := []string{"file_open /ws/notes.txt", "file_open /home/u/.claude/plugins/installed_plugins.json", "file_write /ws/notes.txt", "file_open /ws/notes.txt"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

// The harness's read and delete of its cwd file, merged into one batch, reach
// the probe as an ambiguous open and an ambiguous delete of /tmp (I-43). Only
// that shape becomes a read of the cwd file; every other event on /tmp keeps
// its target. Events of one batch are a nanosecond apart, as the probe stamps
// them.
func TestFoldCwdFileReadTakesOnlyTheHarnessShape(t *testing.T) {
	const pid, other = 9, 10
	ev := func(ns int, typ models.ActionType, target string, p uint32, amb bool) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: t0.Add(time.Duration(ns)), ActionType: typ, Target: target, PID: p, PathIsAmbiguous: amb}
	}
	tasks := "/tmp/claude-1000/-w/s/tasks"
	cases := []struct {
		name string
		g    models.GroundTruth
		want string // the open's target after the fold
	}{
		{"read and delete in one batch", models.GroundTruth{
			ev(0, models.FileOpen, tasks, pid, true),
			ev(1, models.FileOpen, "/tmp", pid, true),
			ev(2, models.FileDelete, tasks, pid, true),
			ev(3, models.FileDelete, "/tmp", pid, true),
		}, cwdFileRead},
		{"events of another process between", models.GroundTruth{
			ev(0, models.FileOpen, "/tmp", pid, true),
			ev(1, models.FileWrite, "/tmp", other, true),
			ev(2, models.FileDelete, "/tmp", pid, true),
		}, cwdFileRead},
		{"no delete", models.GroundTruth{
			ev(0, models.FileOpen, "/tmp", pid, true),
			ev(1, models.FileOpen, tasks, pid, true),
		}, "/tmp"},
		{"a write of the process on /tmp first", models.GroundTruth{
			ev(0, models.FileOpen, "/tmp", pid, true),
			ev(1, models.FileWrite, "/tmp", pid, true),
			ev(2, models.FileDelete, "/tmp", pid, true),
		}, "/tmp"},
		{"the delete in a later batch", models.GroundTruth{
			ev(0, models.FileOpen, "/tmp", pid, true),
			ev(20000, models.FileDelete, "/tmp", pid, true),
		}, "/tmp"},
		{"the delete by another process", models.GroundTruth{
			ev(0, models.FileOpen, "/tmp", pid, true),
			ev(1, models.FileDelete, "/tmp", other, true),
		}, "/tmp"},
		{"a named delete", models.GroundTruth{
			ev(0, models.FileOpen, "/tmp", pid, true),
			ev(1, models.FileDelete, "/tmp", pid, false),
		}, "/tmp"},
		{"a named open of /tmp", models.GroundTruth{
			ev(0, models.FileOpen, "/tmp", pid, false),
			ev(1, models.FileDelete, "/tmp", pid, true),
		}, "/tmp"},
		{"an ambiguous open of another directory", models.GroundTruth{
			ev(0, models.FileOpen, "/var/tmp", pid, true),
			ev(1, models.FileDelete, "/var/tmp", pid, true),
		}, "/var/tmp"},
	}
	for _, c := range cases {
		in := append(models.GroundTruth(nil), c.g...)
		out := foldCwdFileRead(in)
		if len(out) != len(c.g) {
			t.Fatalf("%s: %d events, want %d", c.name, len(out), len(c.g))
		}
		var open *models.GroundTruthEvent
		for i := range out {
			if out[i].ActionType == models.FileOpen && out[i].PID == pid && out[i].Target != tasks {
				open = &out[i]
				break
			}
		}
		if open == nil || open.Target != c.want {
			t.Errorf("%s: open %+v, want target %s", c.name, open, c.want)
			continue
		}
		if open.Target == cwdFileRead && open.PathIsAmbiguous {
			t.Errorf("%s: the rewritten open is still ambiguous", c.name)
		}
		for i := range in {
			if in[i] != c.g[i] {
				t.Errorf("%s: the input was modified at %d", c.name, i)
			}
		}
	}
}

// The rewritten open names the cwd file family the way a named read of one
// does where runs are compared, and it is the harness's own path (I-43).
func TestTheFoldedCwdFileReadIsCanonicalAndHarnessOwned(t *testing.T) {
	named := Adapter{}.Canonical(models.GroundTruthEvent{ActionType: models.FileOpen, Target: "/tmp/claude-8e2a-cwd"})
	folded := Adapter{}.Canonical(models.GroundTruthEvent{ActionType: models.FileOpen, Target: cwdFileRead})
	if named.Target != folded.Target {
		t.Errorf("canonical %q and %q differ", named.Target, folded.Target)
	}
	if !(Adapter{}).IsHarnessOwned(cwdFileRead) {
		t.Errorf("%s is not harness-owned", cwdFileRead)
	}
	if cwdFileID.MatchString(cwdFileRead) {
		t.Errorf("%s has the shape of a real cwd file", cwdFileRead)
	}
}
