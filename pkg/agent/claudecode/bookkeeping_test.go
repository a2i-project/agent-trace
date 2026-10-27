package claudecode

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// V-50: the declaration names the version lock of the session's own version
// and its temporary, with the kinds the harness's rewrite produces, and
// nothing else.
func TestHarnessBookkeepingDeclaresTheVersionLockOnly(t *testing.T) {
	const locks = "/home/u/.local/state/claude/locks/"
	ev := func(typ models.ActionType, target string) models.GroundTruthEvent {
		return models.GroundTruthEvent{ActionType: typ, Target: target}
	}
	for _, c := range []struct {
		version, home string
		e             models.GroundTruthEvent
		want          bool
	}{
		{"2.1.306", "/home/u", ev(models.FileRename, locks+"2.1.306.lock"), true},
		{"2.1.306", "/home/u", ev(models.FileOpen, locks+"2.1.306.lock"), true},
		{"2.1.306", "/home/u", ev(models.FileWrite, locks+"2.1.306.lock"), true},
		{"2.1.306", "/home/u", ev(models.FileClose, locks+"2.1.306.lock"), true},
		{"2.1.306", "/home/u", ev(models.FileDelete, locks+"2.1.306.lock"), true},
		{"2.1.306", "/home/u", ev(models.FileWrite, locks+"2.1.306.lock.tmp.6d46be80"), true},
		{"2.1.306", "/home/u", ev(models.FileOpen, locks+"2.1.306.lock.tmp.6d46be80"), true},
		{"2.1.306", "/home/u", ev(models.FileClose, locks+"2.1.306.lock.tmp.6d46be80"), true},
		{"2.1.306", "/home/u", ev(models.FileRename, locks+"2.1.306.lock.tmp.6d46be80"), true},
		{"2.1.306", "", ev(models.FileRename, locks+"2.1.306.lock"), true},
		{"2.1.306", "", ev(models.FileRename, "/root/.local/state/claude/locks/2.1.306.lock"), true},
		{"2.1.306", "/root", ev(models.FileRename, "/root/.local/state/claude/locks/2.1.306.lock"), true},
		// A kind no rewrite produced.
		{"2.1.306", "/home/u", ev(models.FileDelete, locks+"2.1.306.lock.tmp.6d46be80"), false},
		{"2.1.306", "/home/u", ev(models.ProcessExec, locks+"2.1.306.lock"), false},
		{"2.1.306", "/home/u", ev(models.NetConnect, locks+"2.1.306.lock"), false},
		// Another version, the directory, another file there, a wrong
		// temporary name.
		{"2.1.306", "/home/u", ev(models.FileWrite, locks+"2.1.305.lock"), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, locks+"2.1.3060.lock"), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, locks+"2x1.306.lock"), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, "/home/u/.local/state/claude/locks"), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, locks), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, locks+"2.1.306.lock.bak"), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, locks+"2.1.306.lock/x"), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, locks+"2.1.306.lock.tmp.6D46BE80"), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, locks+"2.1.306.lock.tmp.6d46be8"), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, locks+"2.1.306.lock.tmp.6d46be801"), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, locks+"2.1.306.lock.tmp."), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, "/home/u/.local/state/claude/2.1.306.lock"), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, "/ws/.local/state/claude/locks/2.1.306.lock"), false},
		// Another home than the one the capture recorded.
		{"2.1.306", "/home/u", ev(models.FileWrite, "/home/v/.local/state/claude/locks/2.1.306.lock"), false},
		{"2.1.306", "/home/u", ev(models.FileWrite, "/root/.local/state/claude/locks/2.1.306.lock"), false},
	} {
		bk := Adapter{}.HarnessBookkeeping(c.version, c.home)
		if bk == nil {
			t.Fatalf("version %q home %q: no declaration", c.version, c.home)
		}
		if got := bk(c.e); got != c.want {
			t.Errorf("version %q home %q, %s %s: %v, want %v", c.version, c.home, c.e.ActionType, c.e.Target, got, c.want)
		}
	}
	for _, c := range []struct{ version, home string }{
		{"", "/home/u"}, {"2.1", "/home/u"}, {"2.1.306-beta", "/home/u"}, {"../x", "/home/u"}, {"2.1.*", "/home/u"},
		{"2.1.306", "/home/u/"}, {"2.1.306", "/home/u/../v"}, {"2.1.306", "/tmp"}, {"2.1.306", "/home"}, {"2.1.306", "relative"},
	} {
		if (Adapter{}).HarnessBookkeeping(c.version, c.home) != nil {
			t.Errorf("version %q home %q: a declaration, want none", c.version, c.home)
		}
	}
}

// V-50 on the shape of the third long pilot of 2.1.306, synthesized: the
// harness writes its lock's temporary, the probe reports the temporary's
// rename before its open, write and close, then the rename onto the lock;
// the fold of NormalizeStream does not take that order. With the controls'
// rules for the lock's opens and delete, the six events are declared
// bookkeeping and the run is FAITHFUL; without the session's version, or for
// another version, they stay unexplained harness activity.
func TestThePilotLockRewriteIsDeclaredBookkeeping(t *testing.T) {
	const (
		root = 100
		home = "/home/u"
		lock = home + "/.local/state/claude/locks/2.1.306.lock"
		tmp  = lock + ".tmp.0a1b2c3d"
	)
	ts := time.Date(2026, 10, 27, 10, 51, 41, 230847411, time.UTC)
	ev := func(ns int, typ models.ActionType, target string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: ts.Add(time.Duration(ns)), ActionType: typ, Target: target, PID: root}
	}
	capture := func(extra ...models.GroundTruthEvent) models.GroundTruthFile {
		return models.GroundTruthFile{
			RootPID: root, Workspace: "/ws",
			Coverage:  &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}},
			Sensitive: &models.SensitiveSnapshot{Home: home},
			Events: append(models.GroundTruth{
				ev(0, models.FileWrite, tmp),
				ev(1, models.FileRename, tmp),
				ev(2, models.FileOpen, tmp),
				ev(2, models.FileWrite, tmp),
				ev(2, models.FileClose, tmp),
				ev(4, models.FileRename, lock),
				ev(5, models.FileOpen, lock),
				ev(int(4*time.Minute), models.FileOpen, lock),
				ev(int(4*time.Minute)+3000, models.FileDelete, lock),
			}, extra...),
		}
	}
	// The pilot's baseline holds rules for the lock's open and delete, and
	// for the write its controls' rewrites fold to.
	measured := func(e models.GroundTruthEvent) bool {
		return e.Target == lock && (e.ActionType == models.FileOpen || e.ActionType == models.FileDelete || e.ActionType == models.FileWrite)
	}
	verify := func(version string, g models.GroundTruthFile) verification.Verdict {
		in := agent.Prepare(Adapter{}, nil, g, measured, verification.Options{})
		in.Options.HarnessBookkeeping = agent.HarnessBookkeeping(Adapter{}, version, g)
		return verification.Verify(in)
	}

	v := verify("2.1.306", capture())
	if v.Outcome != verification.OutcomeFaithful || len(v.HarnessBookkeeping) != 6 || len(v.UnexplainedHarness) != 0 || v.Coverage.BaselinedLevelZero != 3 {
		t.Fatalf("outcome %s, bookkeeping %v, harness %v, baselined %d, reasons %v", v.Outcome, v.HarnessBookkeeping, v.UnexplainedHarness, v.Coverage.BaselinedLevelZero, v.Reasons)
	}
	for _, version := range []string{"", "2.1.305"} {
		v = verify(version, capture())
		if v.Outcome != verification.OutcomeInconclusive || len(v.UnexplainedHarness) != 6 || len(v.HarnessBookkeeping) != 0 {
			t.Errorf("version %q: outcome %s, harness %v, bookkeeping %v", version, v.Outcome, v.UnexplainedHarness, v.HarnessBookkeeping)
		}
	}
	// What an agent could put there: another version's lock, a file beside
	// the lock, the lock in another home. Each stays unexplained harness
	// activity, so the run is not FAITHFUL.
	for _, target := range []string{
		home + "/.local/state/claude/locks/2.1.305.lock",
		home + "/.local/state/claude/locks/payload",
		"/home/v/.local/state/claude/locks/2.1.306.lock",
	} {
		v = verify("2.1.306", capture(ev(int(time.Minute), models.FileWrite, target)))
		if v.Outcome != verification.OutcomeInconclusive || len(v.UnexplainedHarness) != 1 || v.UnexplainedHarness[0].Target != target {
			t.Errorf("%s: outcome %s, harness %v", target, v.Outcome, v.UnexplainedHarness)
		}
	}
}
