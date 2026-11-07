package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// V-104: the open with which the agent's own process copies a file a claim
// wrote earlier into the session's checkpoint (TraceDecl.Checkpoint) is
// explained as bookkeeping: the last open of the file before the
// process's first event on a checkpoint version of it, with the content
// the version's close holds. Every other open of the file stays checked.
func TestVerify_TheHarnessCheckpointCopyOfAnEditedFileIsExplained(t *testing.T) {
	const (
		file    = "/ws/a.py"
		version = "/h/file-history/S/a@v2"
		other   = "/h/file-history/T/a@v2"
	)
	h0, h1, h2 := "sha256:00", "sha256:11", "sha256:22"
	str := func(s string) *string { return &s }
	end := func(c models.TrajectoryEntry, ms int) models.TrajectoryEntry {
		e := at(ms)
		c.End = &e
		return c
	}
	open := func(ms int, pid uint32, hash string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at(ms), ActionType: models.FileOpen, Target: file, PID: pid, InputHash: str(hash)}
	}
	// The edit: a claimed open and write of the file, ended at 110.
	editOpen := claimAt(100, models.FileOpen, file)
	editOpen.InputHash = str(h0)
	editWrite := claimAt(100, models.FileWrite, file)
	editWrite.OutputHash = str(h1)
	edit := models.Trajectory{end(editOpen, 110), end(editWrite, 110)}
	editEvents := []models.GroundTruthEvent{
		open(101, agentPID, h0),
		{Timestamp: at(105), ActionType: models.FileWrite, Target: file, PID: agentPID, OutputHash: str(h1)},
	}
	// copyTo is the harness's copy in Claude Code's shape: the version is
	// written, opened, written and closed with the content hash.
	copyTo := func(ms int, path, hash string) []models.GroundTruthEvent {
		return []models.GroundTruthEvent{
			{Timestamp: at(ms), ActionType: models.FileWrite, Target: path, PID: agentPID},
			{Timestamp: at(ms), ActionType: models.FileOpen, Target: path, PID: agentPID, InputHash: str("sha256:e3")},
			{Timestamp: at(ms), ActionType: models.FileWrite, Target: path, PID: agentPID},
			{Timestamp: at(ms), ActionType: models.FileClose, Target: path, PID: agentPID, OutputHash: str(hash)},
		}
	}
	checkpoint := func(f, w string) bool { return f == file && w == version }
	owned := func(p string) bool { return strings.HasPrefix(p, "/h/") }
	bookkeeping := func(e models.GroundTruthEvent) bool { return strings.HasPrefix(e.Target, "/h/file-history/") }
	verify := func(claims models.Trajectory, decl func(string, string) bool, g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(),
			Trace:   TraceInput{Decl: &TraceDecl{Covers: func(string) bool { return false }, Checkpoint: decl}},
			Options: Options{HarnessOwned: owned, HarnessBookkeeping: bookkeeping, CollapseOpenRuns: true}})
	}
	ground := func(extra ...models.GroundTruthEvent) []models.GroundTruthEvent {
		return append(append([]models.GroundTruthEvent{}, editEvents...), extra...)
	}
	honest := func() []models.GroundTruthEvent {
		return ground(append([]models.GroundTruthEvent{open(500, agentPID, h1)}, copyTo(500, version, h1)...)...)
	}
	isCopy := func(e models.GroundTruthEvent) bool {
		return e.ActionType == models.FileOpen && e.Target == file && e.Timestamp.Equal(at(500))
	}
	copied := func(v Verdict) int {
		n := 0
		for _, e := range v.HarnessBookkeeping {
			if e.Target == file {
				n++
			}
		}
		return n
	}

	t.Run("the copy's open after an edit is explained: faithful", func(t *testing.T) {
		v := verify(edit, checkpoint, honest()...)
		wantOutcome(t, v, OutcomeFaithful)
		if copied(v) != 1 || len(v.HarnessBookkeeping) != 5 || !isCopy(v.HarnessBookkeeping[len(v.HarnessBookkeeping)-1]) {
			t.Errorf("bookkeeping=%v", v.HarnessBookkeeping)
		}
	})
	t.Run("without a declaration the copy's open is Unrecorded", func(t *testing.T) {
		v := verify(edit, nil, honest()...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || !isCopy(v.Unrecorded[0]) {
			t.Errorf("unrecorded=%v", v.Unrecorded)
		}
	})
	t.Run("an unclaimed read of the edited file with no copy after it stays Unrecorded", func(t *testing.T) {
		v := verify(edit, checkpoint, ground(open(500, agentPID, h1))...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || copied(v) != 0 {
			t.Errorf("unrecorded=%v bookkeeping=%v", v.Unrecorded, v.HarnessBookkeeping)
		}
	})
	t.Run("a copy into another session's directory explains nothing", func(t *testing.T) {
		v := verify(edit, checkpoint, ground(append([]models.GroundTruthEvent{open(500, agentPID, h1)}, copyTo(500, other, h1)...)...)...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || copied(v) != 0 {
			t.Errorf("unrecorded=%v bookkeeping=%v", v.Unrecorded, v.HarnessBookkeeping)
		}
	})
	t.Run("a copy with another content explains nothing", func(t *testing.T) {
		v := verify(edit, checkpoint, ground(append([]models.GroundTruthEvent{open(500, agentPID, h1)}, copyTo(500, version, h2)...)...)...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || copied(v) != 0 {
			t.Errorf("unrecorded=%v bookkeeping=%v", v.Unrecorded, v.HarnessBookkeeping)
		}
	})
	t.Run("a copy without a content hash explains nothing", func(t *testing.T) {
		c := copyTo(500, version, h1)
		c[3].OutputHash = nil
		v := verify(edit, checkpoint, ground(append([]models.GroundTruthEvent{open(500, agentPID, h1)}, c...)...)...)
		if len(v.Unrecorded) != 1 || copied(v) != 0 {
			t.Errorf("unrecorded=%v bookkeeping=%v", v.Unrecorded, v.HarnessBookkeeping)
		}
	})
	t.Run("only the last open before the copy is taken: an earlier read stays Unrecorded", func(t *testing.T) {
		g := ground(append([]models.GroundTruthEvent{open(300, agentPID, h1), agentEv(301, models.FileOpen, "/ws/b.py"), open(500, agentPID, h1)}, copyTo(500, version, h1)...)...)
		v := verify(edit, checkpoint, g...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if copied(v) != 1 || len(v.Unrecorded) != 2 || !v.Unrecorded[0].Timestamp.Equal(at(300)) {
			t.Errorf("unrecorded=%v bookkeeping=%v", v.Unrecorded, v.HarnessBookkeeping)
		}
	})
	t.Run("a command's open does not count", func(t *testing.T) {
		cat := end(claimAt(490, models.ProcessExec, "/usr/bin/cat "+file), 510)
		g := ground(fork(495, 200, agentPID), execEv(496, 200, agentPID, "/usr/bin/cat "+file), open(497, 200, h1))
		g = append(g, copyTo(500, version, h1)...)
		v := verify(append(edit, cat), checkpoint, g...)
		wantOutcome(t, v, OutcomeFaithful)
		if copied(v) != 0 {
			t.Errorf("bookkeeping=%v", v.HarnessBookkeeping)
		}
	})
	t.Run("a file no claim wrote before the copy explains nothing", func(t *testing.T) {
		read := end(claimAt(100, models.FileOpen, file), 110)
		read.InputHash = str(h0)
		g := []models.GroundTruthEvent{open(101, agentPID, h0), open(500, agentPID, h0)}
		v := verify(models.Trajectory{read}, checkpoint, append(g, copyTo(500, version, h0)...)...)
		// The second open joins the read's run (V-49): it is not taken.
		if len(v.RepeatedOpens) != 1 || copied(v) != 0 {
			t.Errorf("repeated=%v bookkeeping=%v", v.RepeatedOpens, v.HarnessBookkeeping)
		}
		// The write claim must end before the copy's earliest moment.
		late := models.Trajectory{end(editOpen, 110), end(editWrite, 600)}
		v = verify(late, checkpoint, honest()...)
		if copied(v) != 0 {
			t.Errorf("a copy inside the edit was taken: %v", v.HarnessBookkeeping)
		}
	})
	t.Run("a checkpoint path a claim names explains nothing", func(t *testing.T) {
		w := end(claimAt(499, models.FileWrite, version), 501)
		w.OutputHash = str(h1)
		v := verify(append(edit, w), checkpoint, honest()...)
		if copied(v) != 0 {
			t.Errorf("bookkeeping=%v", v.HarnessBookkeeping)
		}
	})
	t.Run("a later claimed read pairs with its own open, not the copy's", func(t *testing.T) {
		read := end(claimAt(600, models.FileOpen, file), 610)
		read.InputHash = str(h1)
		v := verify(append(edit, read), checkpoint, append(honest(), open(601, agentPID, h1))...)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.OutsideInterval) != 0 || copied(v) != 1 {
			t.Errorf("outside=%v bookkeeping=%v", v.OutsideInterval, v.HarnessBookkeeping)
		}
	})
	t.Run("a capture without a root takes nothing", func(t *testing.T) {
		if got := checkpointOpens(checkpoint, honest(), edit, nil, nil, 0); got != nil {
			t.Errorf("checkpointOpens = %v", got)
		}
	})
	t.Run("the open's earliest moment decides the order", func(t *testing.T) {
		g := honest()
		nb := at(105)
		g[2].NotBefore = &nb // the copy's open may have happened before the edit ended
		v := verify(edit, checkpoint, g...)
		if copied(v) != 0 {
			t.Errorf("bookkeeping=%v", v.HarnessBookkeeping)
		}
	})
}
