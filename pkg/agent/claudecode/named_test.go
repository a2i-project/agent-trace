package claudecode

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The tests in this file mirror the fold tests of stream_test.go and
// inplace_test.go in the shape the probe reports since it names directory
// entries (P-25, I-56): the create names the temporary, the open, writes and
// close name the temporary even when read after the rename, and the rename is
// two events, its source naming the temporary and its destination the
// target. Nothing is ambiguous. The checked-in captures hold only the older
// shapes, which the tests in stream_test.go cover.

// namedWrite is a replace read as it happened: the create, open, write and
// close of the temporary, then the rename's source and destination.
func namedWrite(ms int, path, tmpSuffix, hash string, pid uint32) models.GroundTruth {
	tmp := path + ".tmp." + tmpSuffix
	return models.GroundTruth{
		fev(ms, models.FileWrite, tmp, pid),
		fev(ms, models.FileOpen, tmp, pid),
		fev(ms+1, models.FileWrite, tmp, pid),
		hashed(fev(ms+2, models.FileClose, tmp, pid), hash),
		fev(ms+3, models.FileRename, tmp, pid),
		fev(ms+3, models.FileRename, path, pid),
	}
}

// namedWriteMerged is the same replace read after the rename: the kernel
// merged the rename's source into the create's unread record, so the two are
// one record, at one time, ahead of the open (measured on kernel 6.17,
// 12_probe_fs.md). The open, write and close still name the temporary.
func namedWriteMerged(ms int, path, tmpSuffix, hash string, pid uint32) models.GroundTruth {
	tmp := path + ".tmp." + tmpSuffix
	return models.GroundTruth{
		fev(ms, models.FileWrite, tmp, pid),
		fev(ms, models.FileRename, tmp, pid),
		fev(ms, models.FileOpen, tmp, pid),
		fev(ms, models.FileWrite, tmp, pid),
		hashed(fev(ms, models.FileClose, tmp, pid), hash),
		fev(ms, models.FileRename, path, pid),
	}
}

func joined(g models.GroundTruth) string { return strings.Join(targets(g), "|") }

// I-22, I-32 and I-34 named: in either read order a replace folds into one
// write of the target, at the create's time, with the close's hash.
func TestNamedFoldTurnsAReplaceIntoOneWriteWithTheFinalHash(t *testing.T) {
	for name, g := range map[string]models.GroundTruth{
		"read before the rename": namedWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:final", 100),
		"read after the rename":  namedWriteMerged(10, "/w/a.txt", "100.5b5474087431", "sha256:final", 100),
		"two writes": append(namedWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:final", 100)[:3],
			append(models.GroundTruth{fev(11, models.FileWrite, "/w/a.txt.tmp.100.5b5474087431", 100)},
				namedWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:final", 100)[3:]...)...),
	} {
		t.Run(name, func(t *testing.T) {
			got := Adapter{}.NormalizeStream(g)
			if len(got) != 1 || got[0].ActionType != models.FileWrite || got[0].Target != "/w/a.txt" || got[0].PID != 100 || got[0].PathIsAmbiguous {
				t.Fatalf("folded = %v, want one write of /w/a.txt", targets(got))
			}
			if got[0].OutputHash == nil || *got[0].OutputHash != "sha256:final" {
				t.Errorf("hash = %v, want the close's", got[0].OutputHash)
			}
			if !got[0].Timestamp.Equal(at(10)) {
				t.Errorf("timestamp = %v, want the create's", got[0].Timestamp)
			}
		})
	}
}

// Names are evidence: every one of the six events is required and must name
// the temporary or the target exactly, where the older shapes accepted a
// directory. Each case below leaves the events as the probe reported them.
func TestNamedFoldRequiresEveryNameOfTheReplace(t *testing.T) {
	const tmp, x = "/w/a.txt.tmp.100.5b5474087431", "/w/a.txt"
	base := func() models.GroundTruth { return namedWrite(10, x, "100.5b5474087431", "sha256:h", 100) }
	without := func(i int) models.GroundTruth {
		g := base()
		return append(g[:i:i], g[i+1:]...)
	}
	with := func(i int, e models.GroundTruthEvent) models.GroundTruth {
		g := base()
		g[i] = e
		return g
	}
	for name, g := range map[string]models.GroundTruth{
		"no create":                         without(0),
		"no close":                          without(3),
		"no source":                         without(4),
		"no destination":                    without(5),
		"a create of another file":          with(0, fev(10, models.FileWrite, "/w/b.txt", 100)),
		"a close of the target":             with(3, hashed(fev(12, models.FileClose, x, 100), "sha256:h")),
		"a source naming another temporary": with(4, fev(13, models.FileRename, "/w/a.txt.tmp.100.000000000000", 100)),
		"a source naming the target":        with(4, fev(13, models.FileRename, x, 100)),
		"a destination naming another file": with(5, fev(13, models.FileRename, "/w/b.txt", 100)),
		"a destination by another process":  with(5, fev(13, models.FileRename, x, 200)),
		"an ambiguous destination":          with(5, dirEv(13, models.FileRename, 100)),
		"a merged source at another time": {
			fev(10, models.FileWrite, tmp, 100), fev(11, models.FileRename, tmp, 100),
			fev(12, models.FileOpen, tmp, 100), hashed(fev(12, models.FileClose, tmp, 100), "sha256:h"),
			fev(13, models.FileRename, x, 100),
		},
		// I-34 named: a write of the target while the temporary is open is
		// not the replace's, and ends the shape.
		"a write of the target before the close": {
			fev(10, models.FileWrite, tmp, 100), fev(10, models.FileOpen, tmp, 100),
			fev(11, models.FileWrite, x, 100), hashed(fev(12, models.FileClose, tmp, 100), "sha256:h"),
			fev(13, models.FileRename, tmp, 100), fev(13, models.FileRename, x, 100),
		},
		"an open of the target between the source and the destination": {
			fev(10, models.FileWrite, tmp, 100), fev(10, models.FileOpen, tmp, 100),
			hashed(fev(12, models.FileClose, tmp, 100), "sha256:h"),
			fev(13, models.FileRename, tmp, 100), fev(13, models.FileOpen, x, 100), fev(14, models.FileRename, x, 100),
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := foldAtomicWrites(g)
			if joined(got) != joined(g) {
				t.Errorf("folded: %v, want %v", targets(got), targets(g))
			}
		})
	}
}

// I-33 named: the halves of a rename name different paths, so there is no
// split to take; a further rename of the target after the destination is a
// rename of its own and stays.
func TestNamedFoldTakesNoFurtherRename(t *testing.T) {
	g := append(namedWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:h", 100),
		fev(14, models.FileRename, "/w/a.txt", 100), fev(20, models.FileOpen, "/w/after", 100))
	want := "file_write /w/a.txt|file_rename /w/a.txt|file_open /w/after"
	if got := (Adapter{}).NormalizeStream(g); joined(got) != want {
		t.Errorf("got %v, want %s", targets(got), want)
	}
}

// A second replace of the target with nothing on the target since the first
// one's destination has no destination of its own: the probe drops a rename
// that repeats the last event on its path by the same process (P-18), as the
// kernel does when it merges the record into an unread one. It folds. With an
// event on the target between, the drop cannot have happened and the replace
// stays as it was reported.
func TestNamedFoldTakesADestinationTheProbeCollapsed(t *testing.T) {
	first := namedWrite(10, "/h/.claude.json", "100.111111111111", "sha256:1", 100)
	second := namedWrite(30, "/h/.claude.json", "100.222222222222", "sha256:2", 100)
	collapsed := append(append(models.GroundTruth{}, first...), second[:5]...)
	got := foldAtomicWrites(collapsed)
	if joined(got) != "file_write /h/.claude.json|file_write /h/.claude.json" || *got[1].OutputHash != "sha256:2" {
		t.Errorf("collapsed destination: got %v", targets(got))
	}

	read := append(append(models.GroundTruth{}, first...), fev(20, models.FileOpen, "/h/.claude.json", 100))
	read = append(read, second[:5]...)
	got = foldAtomicWrites(read)
	want := "file_write /h/.claude.json|file_open /h/.claude.json|" + joined(second[:5])
	if joined(got) != want {
		t.Errorf("a read between: got %v, want %s", targets(got), want)
	}
	other := append(append(models.GroundTruth{}, first...), fev(20, models.FileRename, "/h/.claude.json", 7))
	other = append(other, second[:5]...)
	if got := foldAtomicWrites(other); len(got) != 2+5 {
		t.Errorf("another process's rename between: got %v", targets(got))
	}
	// A replace whose destination is missing does not borrow the next one's.
	borrow := append(append(models.GroundTruth{}, namedWrite(10, "/w/a.txt", "100.111111111111", "sha256:1", 100)[:5]...),
		namedWrite(30, "/w/a.txt", "100.222222222222", "sha256:2", 100)...)
	got = foldAtomicWrites(borrow)
	if len(got) != 6 || got[5].Target != "/w/a.txt" || got[5].OutputHash == nil || *got[5].OutputHash != "sha256:2" {
		t.Errorf("a missing destination: got %v, want the first replace raw and the second folded", targets(got))
	}
}

func TestNamedFoldKeepsEverythingAroundTheReplace(t *testing.T) {
	g := models.GroundTruth{fev(0, models.FileOpen, "/w/before", 100)}
	g = append(g, namedWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:h", 100)...)
	g = append(g, fev(20, models.FileOpen, "/w/after", 100))
	if got, want := joined((Adapter{}).NormalizeStream(g)), "file_open /w/before|file_write /w/a.txt|file_open /w/after"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// Other processes' events, and the process's own events on other paths (its
// other threads share its pid), interleave with the replace and stay.
func TestNamedFoldIgnoresInterleavedEvents(t *testing.T) {
	r := namedWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:h", 100)
	g := models.GroundTruth{r[0], r[1], fev(10, models.FileOpen, "/w/other", 200), r[2],
		fev(11, models.FileWrite, "/home/u/.claude/projects/-w/s.jsonl", 100), r[3], r[4],
		fev(13, models.FileWrite, "/w/other", 200), r[5]}
	want := "file_write /w/a.txt|file_open /w/other|file_write /home/u/.claude/projects/-w/s.jsonl|file_write /w/other"
	if got := joined((Adapter{}).NormalizeStream(g)); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// I-104: the create of a named replace is taken whatever its distance in
// time from the open, as I-99 and I-101 take a create for Codex and agy:
// where the probe's reads split a burst of records depends on load (P-18),
// so the create and the open may come in two batches, microseconds or more
// apart. The fold judges the names and the order of the process's events
// on the temporary and the target, never their time.
func TestNamedFoldTakesACreateReadInAnEarlierBatch(t *testing.T) {
	const x = "/w/a.txt"
	for name, gap := range map[string]time.Duration{
		"one batch":                          time.Nanosecond,
		"the next batch, 11 microseconds on": 11 * time.Microsecond,
		"a second later":                     time.Second,
	} {
		for shape, g := range map[string]models.GroundTruth{
			"read before the rename": namedWrite(10, x, "100.5b5474087431", "sha256:h", 100),
			"read after the rename":  namedWriteMerged(10, x, "100.5b5474087431", "sha256:h", 100),
			"the version lock":       namedWrite(10, "/home/u/.local/state/claude/locks/2.1.306.lock", "68f796c1", "sha256:h", 100),
		} {
			t.Run(name+"/"+shape, func(t *testing.T) {
				// Every event from the open on moves by the gap; in the
				// merged shape the source stays with the create.
				first := 1
				if g[1].ActionType == models.FileRename {
					first = 2
				}
				for i := first; i < len(g); i++ {
					g[i].Timestamp = g[i].Timestamp.Add(gap)
				}
				got := Adapter{}.NormalizeStream(g)
				if len(got) != 1 || got[0].ActionType != models.FileWrite || got[0].OutputHash == nil || *got[0].OutputHash != "sha256:h" || !got[0].Timestamp.Equal(at(10)) {
					t.Errorf("folded = %v, want one write at the create's time with the close's hash", targets(got))
				}
			})
		}
	}
}

// I-76: the process's events on other paths may also lie between the create
// and the open, and between a merged source and the create, as they may
// after the open. They stay; any event of the process on the target or on
// another temporary of it there ends the shape.
func TestNamedFoldTakesACreateWithOtherPathsBeforeTheOpen(t *testing.T) {
	const tmp, x = "/w/a.txt.tmp.100.5b5474087431", "/w/a.txt"
	other := fev(10, models.FileClose, "/tmp/claude-1000/fswatch-probe-x/probe", 100)
	r := namedWrite(10, x, "100.5b5474087431", "sha256:h", 100)
	m := namedWriteMerged(10, x, "100.5b5474087431", "sha256:h", 100)
	for name, g := range map[string]models.GroundTruth{
		"before the open":              {r[0], other, r[1], r[2], r[3], r[4], r[5]},
		"two before the open":          {r[0], other, fev(10, models.FileOpen, "/w/b", 100), r[1], r[2], r[3], r[4], r[5]},
		"before the open, merged":      {m[0], m[1], other, m[2], m[3], m[4], m[5]},
		"before a merged source":       {m[0], other, m[1], m[2], m[3], m[4], m[5]},
		"and another process's events": {r[0], fev(10, models.FileOpen, x, 200), r[1], r[2], r[3], r[4], r[5]},
	} {
		t.Run(name, func(t *testing.T) {
			got := Adapter{}.NormalizeStream(g)
			var folded []models.GroundTruthEvent
			for _, e := range got {
				if e.Target == x && e.ActionType == models.FileWrite {
					folded = append(folded, e)
				}
				if e.Target == tmp || (e.Target == x && e.ActionType != models.FileWrite && e.PID == 100) {
					t.Errorf("an event of the replace stayed: %v", targets(got))
				}
			}
			if len(folded) != 1 || folded[0].OutputHash == nil || *folded[0].OutputHash != "sha256:h" || !folded[0].Timestamp.Equal(at(10)) {
				t.Errorf("folded = %v, want one write of %s at the create's time with the close's hash", targets(got), x)
			}
			if len(got) != len(g)-5 {
				t.Errorf("got %v: the events on other paths must stay", targets(got))
			}
		})
	}
	for name, g := range map[string]models.GroundTruth{
		"an open of the target":        {r[0], fev(10, models.FileOpen, x, 100), r[1], r[2], r[3], r[4], r[5]},
		"a write of the target":        {r[0], fev(10, models.FileWrite, x, 100), r[1], r[2], r[3], r[4], r[5]},
		"another temporary's create":   {r[0], fev(10, models.FileWrite, x+".tmp.100.000000000000", 100), r[1], r[2], r[3], r[4], r[5]},
		"a merged source at its time":  {m[0], other, fev(11, models.FileRename, tmp, 100), m[2], m[3], m[4], m[5]},
		"a create with a hash":         {hashed(r[0], "sha256:h"), other, r[1], r[2], r[3], r[4], r[5]},
		"a create by another process":  {fev(10, models.FileWrite, tmp, 200), other, r[1], r[2], r[3], r[4], r[5]},
		"no create, only another path": {other, r[1], r[2], r[3], r[4], r[5]},
	} {
		t.Run("not with "+name, func(t *testing.T) {
			if got := foldAtomicWrites(g); joined(got) != joined(g) {
				t.Errorf("folded: %v, want %v", targets(got), targets(g))
			}
		})
	}
}

func TestNamedFoldOnlyRecognisesTheHarnessTemporaryName(t *testing.T) {
	for _, tmp := range []string{"/w/a.txt.tmp", "/w/a.tmp.1.5b5474087431x", "/w/a.txt.tmp.abc.5b5474087431", "/w/a.txt.tmp.100.SHORT"} {
		g := models.GroundTruth{fev(0, models.FileWrite, tmp, 100), fev(0, models.FileOpen, tmp, 100), fev(1, models.FileWrite, tmp, 100),
			hashed(fev(2, models.FileClose, tmp, 100), "sha256:h"), fev(3, models.FileRename, tmp, 100), fev(3, models.FileRename, "/w/a.txt", 100)}
		if got := (Adapter{}).NormalizeStream(g); len(got) != len(g) {
			t.Errorf("%s was folded as if it were a harness temporary: %v", tmp, targets(got))
		}
	}
}

func TestNamedFoldKeepsTwoReplacesApart(t *testing.T) {
	g := append(namedWrite(10, "/w/a.txt", "100.5b5474087431", "sha256:1", 100), namedWriteMerged(30, "/w/b.txt", "100.99c9132148e8", "sha256:2", 100)...)
	got := Adapter{}.NormalizeStream(g)
	if len(got) != 2 || got[0].Target != "/w/a.txt" || got[1].Target != "/w/b.txt" || *got[0].OutputHash != "sha256:1" || *got[1].OutputHash != "sha256:2" {
		t.Errorf("got %v", targets(got))
	}
}

// The paired capture's session replayed in the named shape: the reads of the
// target before a replace are named opens (I-39), and every replace is named.
func namedCapturedSession() models.GroundTruth {
	var g models.GroundTruth
	g = append(g, fev(0, models.FileOpen, "/w/b.txt", 100))
	g = append(g, namedWrite(100, "/w/a.txt", "100.5b5474087431", "sha256:hello", 100)...)
	g = append(g, fev(200, models.FileOpen, "/w/a.txt", 100), fev(201, models.FileOpen, "/w/a.txt", 100), fev(202, models.FileOpen, "/w/a.txt", 100))
	g = append(g, namedWriteMerged(210, "/w/a.txt", "100.7cbe937665de", "sha256:world", 100)...)
	g = append(g, fev(300, models.FileOpen, "/w/b.txt", 100))
	g = append(g, namedWrite(310, "/w/b.txt", "100.99c9132148e8", "sha256:again", 100)...)
	return g
}

func TestTheNamedCapturedSessionVerifiesFaithfulAndCatchesEachLie(t *testing.T) {
	if v := verifyCaptured(t, capturedClaims(), namedCapturedSession()); v.Outcome != verification.OutcomeFaithful {
		t.Fatalf("outcome = %s\nunwitnessed=%v\nunrecorded=%v\nmismatched=%v", v.Outcome, v.Unwitnessed, v.Unrecorded, v.Mismatched)
	}
	lies := map[string]func(tr models.Trajectory) models.Trajectory{
		"another content hash": func(tr models.Trajectory) models.Trajectory { tr[1].OutputHash = strPtr("sha256:benign"); return tr },
		"another file":         func(tr models.Trajectory) models.Trajectory { tr[1].Target = "/w/decoy.txt"; return tr },
		"a write omitted": func(tr models.Trajectory) models.Trajectory {
			return append(append(models.Trajectory{}, tr[:1]...), tr[2:]...)
		},
		"a write fabricated": func(tr models.Trajectory) models.Trajectory {
			return append(tr, models.TrajectoryEntry{Timestamp: at(400), ActionType: models.FileWrite, Target: "/w/ghost", Tool: "Write"})
		},
	}
	for name, lie := range lies {
		t.Run(name, func(t *testing.T) {
			if v := verifyCaptured(t, lie(append(models.Trajectory{}, capturedClaims()...)), namedCapturedSession()); v.Outcome != verification.OutcomeNotFaithful {
				t.Errorf("outcome = %s, want NOT FAITHFUL", v.Outcome)
			}
		})
	}
	g := append(namedCapturedSession(), namedWrite(500, "/w/secret", "100.aaaaaaaaaaaa", "sha256:x", 100)...)
	if v := verifyCaptured(t, capturedClaims(), g); v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != "/w/secret" {
		t.Errorf("an unclaimed replace: outcome = %s, unrecorded = %v", v.Outcome, v.Unrecorded)
	}
}

// I-39 named: the read before a replace is a named open of the target, in
// whichever order the batches were read, so a NotebookEdit and an overwriting
// Write each pair their open and their write; with no read observed the
// notebook's claimed open is unwitnessed.
func TestTheNamedReadBeforeAReplaceVerifies(t *testing.T) {
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
	g := models.GroundTruth{fev(0, models.FileOpen, nb, agentPID)}
	g = append(g, namedWriteMerged(1, nb, "100.a5e8eefa3361", nbHash, agentPID)...)
	g = append(g, fev(100, models.FileOpen, rep, agentPID))
	g = append(g, namedWrite(101, rep, "100.0123456789ab", repHash, agentPID)...)
	if v := verifyCaptured(t, claims, g); v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 4 {
		t.Errorf("outcome = %s, corroborated = %d\nunwitnessed=%v\nunrecorded=%v\nmismatched=%v", v.Outcome, len(v.Corroborated), v.Unwitnessed, v.Unrecorded, v.Mismatched)
	}
	if v := verifyCaptured(t, claims, g[1:]); v.Outcome != verification.OutcomeNotFaithful || len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != nb {
		t.Errorf("no read observed: outcome = %s, unwitnessed = %v, want the notebook's open", v.Outcome, v.Unwitnessed)
	}
}

// An Edit's named reads, with a harness read between, and its merged replace:
// one open with the first read's input hash, then the folded write.
func TestTheNamedReadsOfAnEditCollapse(t *testing.T) {
	const pid = 9
	in := "sha256:eb87ce4"
	named := fev(0, models.FileOpen, "/ws/notes.txt", pid)
	named.InputHash = &in
	g := models.GroundTruth{named, named, fev(5, models.FileOpen, "/home/u/.claude/plugins/installed_plugins.json", pid), named}
	g = append(g, namedWriteMerged(10, "/ws/notes.txt", "9.3a597989445f", "sha256:a5eeda1", pid)...)
	out := Adapter{}.NormalizeStream(g)
	want := "file_open /ws/notes.txt|file_open /home/u/.claude/plugins/installed_plugins.json|file_write /ws/notes.txt"
	if joined(out) != want {
		t.Fatalf("got %v, want %s", targets(out), want)
	}
	if out[0].InputHash == nil || *out[0].InputHash != in {
		t.Errorf("open = %+v, want the first named open's input hash", out[0])
	}
}

// I-44 named: the version lock's rewrite is the temporary shape with names,
// in any read order, followed by the harness's read-back open of the lock. It
// folds into the write and keeps the open, as the older shapes do.
func TestTheNamedLockRewriteFolds(t *testing.T) {
	const pid = 7
	lock := "/home/u/.local/state/claude/locks/2.1.296.lock"
	for name, r := range map[string]models.GroundTruth{
		"read before the rename": namedWrite(0, lock, "68f796c1", "sha256:aa", pid),
		"read after the rename":  namedWriteMerged(0, lock, "68f796c1", "sha256:aa", pid),
	} {
		t.Run(name, func(t *testing.T) {
			g := append(append(models.GroundTruth{}, r...), fev(5, models.FileOpen, lock, pid))
			out := foldAtomicWrites(g)
			if joined(out) != "file_write "+lock+"|file_open "+lock || out[0].OutputHash == nil || *out[0].OutputHash != "sha256:aa" {
				t.Errorf("fold = %v", targets(out))
			}
		})
	}
}

// I-43 named: the harness's read and delete of its cwd file name the file, so
// nothing is rewritten, and the named read is the same where runs are
// compared as the open the fold makes from the ambiguous shape.
func TestTheNamedCwdFileReadNeedsNoFold(t *testing.T) {
	const pid = 9
	ev := func(ns int, typ models.ActionType, target string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: t0.Add(time.Duration(ns)), ActionType: typ, Target: target, PID: pid}
	}
	g := models.GroundTruth{ev(0, models.FileOpen, "/tmp/claude-8e2a-cwd"), ev(1, models.FileDelete, "/tmp/claude-8e2a-cwd")}
	out := Adapter{}.NormalizeStream(g)
	if joined(out) != joined(g) {
		t.Fatalf("got %v, want the events unchanged", targets(out))
	}
	named := Adapter{}.Canonical(out[0])
	folded := Adapter{}.Canonical(foldCwdFileRead(models.GroundTruth{
		{Timestamp: t0, ActionType: models.FileOpen, Target: "/tmp", PID: pid, PathIsAmbiguous: true},
		{Timestamp: t0.Add(1), ActionType: models.FileDelete, Target: "/tmp", PID: pid, PathIsAmbiguous: true},
	})[0])
	if named.Target != folded.Target || named.PathIsAmbiguous || folded.PathIsAmbiguous {
		t.Errorf("canonical named read %+v, folded read %+v: want one target", named, folded)
	}
}

// I-45 named: a rename naming the file, or a temporary of it, just before the
// opens or just after the close is a replace, not an in-place rewrite, and
// the in-place fold leaves it, as it leaves an ambiguous event of the
// directory there.
func TestFoldInPlaceWritesLeavesANamedRenameNextToIt(t *testing.T) {
	const f = "/w/locked/data.txt"
	h := "sha256:after"
	open := fev(0, models.FileOpen, f, agentPID)
	write := fev(1, models.FileWrite, f, agentPID)
	cls := hashed(fev(2, models.FileClose, f, agentPID), h)
	for name, g := range map[string]models.GroundTruth{
		"the file renamed before":          {fev(0, models.FileRename, f, agentPID), open, write, cls},
		"the file renamed after":           {open, write, cls, fev(3, models.FileRename, f, agentPID)},
		"a temporary of it renamed before": {fev(0, models.FileRename, f+".tmp.100.0123456789ab", agentPID), open, write, cls},
	} {
		t.Run(name, func(t *testing.T) {
			if out := foldInPlaceWrites(g); joined(out) != joined(g) {
				t.Errorf("fold = %v, want it left alone", targets(out))
			}
		})
	}
	// A rename of another file there does not stop the fold.
	g := models.GroundTruth{fev(0, models.FileRename, "/w/locked/other.txt", agentPID), open, write, cls}
	if out := foldInPlaceWrites(g); joined(out) != "file_rename /w/locked/other.txt|file_open "+f+"|file_write "+f {
		t.Errorf("fold = %v, want the rewrite folded", targets(out))
	}
}
