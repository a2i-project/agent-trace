package claudecode

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The in-place rewrite, as the `shapes` capture of 2.1.296 showed it on
// 2026-10-13 for a Write and an Edit of a file whose directory was not
// writable: by the agent's process, opens of the file (the first carrying the
// probe's hash of the content before), one write with no hash and the close
// with the hash of the content after, with no temporary, no create and no
// rename (I-45).
func inPlaceWrite(ms int, path, before, after string, opens int) models.GroundTruth {
	var g models.GroundTruth
	for i := 0; i < opens; i++ {
		o := fev(ms, models.FileOpen, path, agentPID)
		o.InputHash = strPtr(before)
		g = append(g, o)
	}
	return append(g, fev(ms+1, models.FileWrite, path, agentPID), hashed(fev(ms+1, models.FileClose, path, agentPID), after))
}

func TestFoldInPlaceWritesTakesOnlyTheHarnessRewrite(t *testing.T) {
	const f = "/w/locked/data.txt"
	h := "sha256:after"
	child := uint32(agentPID + 1)
	open := func(pid uint32) models.GroundTruthEvent { return fev(0, models.FileOpen, f, pid) }
	write := func(pid uint32) models.GroundTruthEvent { return fev(1, models.FileWrite, f, pid) }
	cls := func(pid uint32) models.GroundTruthEvent { return hashed(fev(2, models.FileClose, f, pid), h) }
	dir := func(typ models.ActionType) models.GroundTruthEvent {
		e := fev(0, typ, "/w/locked", agentPID)
		e.PathIsAmbiguous = true
		return e
	}
	folded := []string{"file_open " + f, "file_write " + f}
	for name, tc := range map[string]struct {
		g    models.GroundTruth
		want []string // nil: left as it is
	}{
		"open, write, close": {g: models.GroundTruth{open(agentPID), write(agentPID), cls(agentPID)}, want: folded},
		"two writes before the close": {
			g:    models.GroundTruth{open(agentPID), write(agentPID), write(agentPID), cls(agentPID)},
			want: folded,
		},
		"another process's events between": {
			g:    models.GroundTruth{open(agentPID), fev(0, models.FileOpen, "/etc/x", 7), write(agentPID), fev(1, models.FileWrite, "/w/y", 7), cls(agentPID)},
			want: []string{"file_open " + f, "file_open /etc/x", "file_write " + f, "file_write /w/y"},
		},
		"no open just before the write": {g: models.GroundTruth{write(agentPID), cls(agentPID)}},
		"another event of the process before the close": {
			g: models.GroundTruth{open(agentPID), write(agentPID), fev(1, models.FileOpen, "/w/other", agentPID), cls(agentPID)},
		},
		"another file event between the open and the write": {
			g: models.GroundTruth{open(agentPID), fev(0, models.FileOpen, "/w/other", agentPID), write(agentPID), cls(agentPID)},
		},
		"a process the stream shows starting": {
			g: models.GroundTruth{
				{Timestamp: at(0), ActionType: models.ProcessFork, Target: "101", PID: child, PPID: agentPID},
				{Timestamp: at(0), ActionType: models.ProcessExec, Target: "/bin/bash -c echo x > " + f, PID: child, PPID: agentPID},
				open(child), write(child), cls(child),
			},
		},
		"the harness's own file": {
			g: models.GroundTruth{
				fev(0, models.FileOpen, "/home/u/.claude/projects/-w/s.jsonl", agentPID),
				fev(1, models.FileWrite, "/home/u/.claude/projects/-w/s.jsonl", agentPID),
				hashed(fev(2, models.FileClose, "/home/u/.claude/projects/-w/s.jsonl", agentPID), h),
			},
		},
		"the temporary of an unfinished replace": {
			g: models.GroundTruth{
				fev(0, models.FileOpen, f+".tmp.100.0123456789ab", agentPID),
				fev(1, models.FileWrite, f+".tmp.100.0123456789ab", agentPID),
				hashed(fev(2, models.FileClose, f+".tmp.100.0123456789ab", agentPID), h),
			},
		},
		"a create of the directory before": {g: models.GroundTruth{dir(models.FileWrite), open(agentPID), write(agentPID), cls(agentPID)}},
		"a rename of the directory after":  {g: models.GroundTruth{open(agentPID), write(agentPID), cls(agentPID), dir(models.FileRename)}},
	} {
		t.Run(name, func(t *testing.T) {
			out := foldInPlaceWrites(tc.g)
			want := tc.want
			if want == nil {
				want = targets(tc.g)
			}
			if got := targets(out); strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("fold = %v, want %v", got, want)
			}
			if tc.want == nil {
				return
			}
			for _, e := range out {
				if e.ActionType == models.FileWrite && e.Target == f && (e.OutputHash == nil || *e.OutputHash != h) {
					t.Errorf("folded write %+v, want the close's hash", e)
				}
			}
		})
	}
}

// A Write and an Edit of a file the harness rewrote in place verify like
// replaced ones: each claims an open and a hashed write, and the folded write
// carries the close's hash. The opens collapse, an altered content claim is
// mismatched, and an unclaimed in-place write is still an omission.
func TestAnInPlaceWriteAndEditVerify(t *testing.T) {
	const f = "/w/locked/data.txt"
	v0, v1 := "seed\n", "written\n"
	edit := editResult{original: v1, oldString: "written", newString: "edited"}
	v2 := edit.apply()
	use := func(name, input string) toolUse { return toolUse{id: name, name: name, input: json.RawMessage(input)} }
	var claims models.Trajectory
	for _, c := range []struct {
		u   toolUse
		res toolResult
		ms  int
	}{
		{use(toolWrite, `{"file_path":"`+f+`","content":"written\n"}`), toolResult{kind: "update"}, 0},
		{use(toolEdit, `{"file_path":"`+f+`"}`), toolResult{edit: &edit}, 100},
	} {
		entries, why := claimsFor(c.u, models.TrajectoryEntry{Timestamp: at(c.ms), Tool: c.u.name}, c.res)
		if why != "" {
			t.Fatalf("%s: %s", c.u.name, why)
		}
		claims = append(claims, entries...)
	}
	g := append(inPlaceWrite(0, f, contentHash(v0), contentHash(v1), 2), inPlaceWrite(100, f, contentHash(v1), contentHash(v2), 5)...)

	v := verifyCaptured(t, claims, g)
	if v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 4 || len(v.Unverified) != 0 {
		t.Fatalf("outcome = %s, corroborated = %d\nunverified=%v\nunrecorded=%v\nmismatched=%v", v.Outcome, len(v.Corroborated), v.Unverified, v.Unrecorded, v.Mismatched)
	}

	lie := append(models.Trajectory(nil), claims...)
	lie[3].OutputHash = strPtr(contentHash("benign"))
	if v := verifyCaptured(t, lie, g); v.Outcome != verification.OutcomeNotFaithful || len(v.Mismatched) != 1 {
		t.Errorf("an altered Edit content: outcome = %s, mismatched = %v", v.Outcome, v.Mismatched)
	}

	extra := append(append(models.GroundTruth(nil), g...), inPlaceWrite(500, "/w/secret", contentHash(v0), contentHash("x"), 1)...)
	v = verifyCaptured(t, claims, extra)
	found := false
	for _, e := range v.Unrecorded {
		found = found || (e.ActionType == models.FileWrite && e.Target == "/w/secret")
	}
	if v.Outcome != verification.OutcomeNotFaithful || !found {
		t.Errorf("an unclaimed in-place write: outcome = %s, unrecorded = %v", v.Outcome, v.Unrecorded)
	}
}
