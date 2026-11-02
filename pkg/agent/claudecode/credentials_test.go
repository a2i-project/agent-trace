package claudecode

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/config"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// V-78 on the shape of the two renewing captures of 2.1.306, synthesized:
// the agent's own process replaces ~/.claude/.credentials.json through
// .credentials.json.tmp.<8 hex> (created, opened, written, closed with no
// hash, renamed, then the rename onto the file), which NormalizeStream
// folds into one write of the file. On 2.1.306 that write is declared bookkeeping; for
// another version or with no version it stays unexplained harness
// activity. The same replace through a file tool's temporary, the file
// under another home, a delete of it, and the renewal's lock file and
// backup stay unexplained harness activity.
func TestTheCredentialsRenewalWriteIsDeclaredBookkeeping(t *testing.T) {
	const (
		root  = 100
		home  = "/home/u"
		creds = home + "/.claude/.credentials.json"
		tmp   = creds + ".tmp.cf72da76"
	)
	ts := time.Date(2026, 10, 28, 10, 7, 22, 852461421, time.UTC)
	ev := func(ns int, pid uint32, typ models.ActionType, target string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: ts.Add(time.Duration(ns)), ActionType: typ, Target: target, PID: pid}
	}
	replace := func(ns int, pid uint32, path, temp string) models.GroundTruth {
		return models.GroundTruth{
			ev(ns, pid, models.FileWrite, temp),
			ev(ns+1, pid, models.FileOpen, temp),
			ev(ns+1, pid, models.FileWrite, temp),
			ev(ns+127534, pid, models.FileClose, temp),
			ev(ns+431161, pid, models.FileRename, temp),
			ev(ns+431162, pid, models.FileRename, path),
		}
	}
	capture := func(events ...models.GroundTruthEvent) models.GroundTruthFile {
		return models.GroundTruthFile{
			RootPID: root, Workspace: "/ws",
			Coverage:  &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}},
			Sensitive: &models.SensitiveSnapshot{Home: home},
			Events:    append(models.GroundTruth{ev(-400000000, root, models.FileOpen, creds)}, events...),
		}
	}
	// The controls open the file, so the baseline explains its open.
	measured := func(e models.GroundTruthEvent) bool { return e.Target == creds && e.ActionType == models.FileOpen }
	verify := func(version string, g models.GroundTruthFile) verification.Verdict {
		in := agent.Prepare(Adapter{}, nil, g, measured, verification.Options{})
		in.Options.HarnessBookkeeping = agent.HarnessBookkeeping(Adapter{}, version, g)
		return verification.Verify(in)
	}

	v := verify("2.1.306", capture(replace(0, root, creds, tmp)...))
	if v.Outcome != verification.OutcomeFaithful || len(v.HarnessBookkeeping) != 1 || v.HarnessBookkeeping[0].Target != creds || v.HarnessBookkeeping[0].ActionType != models.FileWrite || len(v.UnexplainedHarness) != 0 {
		t.Fatalf("2.1.306: outcome %s, bookkeeping %v, harness %v, reasons %v", v.Outcome, v.HarnessBookkeeping, v.UnexplainedHarness, v.Reasons)
	}
	for _, version := range []string{"", "2.1.296", "2.1.311"} {
		v = verify(version, capture(replace(0, root, creds, tmp)...))
		if v.Outcome != verification.OutcomeInconclusive || len(v.UnexplainedHarness) != 1 || len(v.HarnessBookkeeping) != 0 {
			t.Errorf("version %q: outcome %s, harness %v, bookkeeping %v", version, v.Outcome, v.UnexplainedHarness, v.HarnessBookkeeping)
		}
	}
	// What an agent's file tool, or the renewal's other files, leave: each
	// folded into one write, none declared.
	for _, c := range []struct{ path, temp string }{
		{creds, creds + ".tmp.4242.0123456789ab"},
		{home + "/.claude/.oauth_refresh.lock.owner", home + "/.claude/.oauth_refresh.lock.owner.tmp.3cea773e"},
		{home + "/.claude/credentials.json", home + "/.claude/credentials.json.tmp.cf72da76"},
	} {
		v = verify("2.1.306", capture(replace(0, root, c.path, c.temp)...))
		if v.Outcome != verification.OutcomeInconclusive || len(v.UnexplainedHarness) != 1 || v.UnexplainedHarness[0].Target != c.path || len(v.HarnessBookkeeping) != 0 {
			t.Errorf("%s through %s: outcome %s, harness %v, bookkeeping %v", c.path, c.temp, v.Outcome, v.UnexplainedHarness, v.HarnessBookkeeping)
		}
	}
	// A delete of the file, and the backup the renewal writes.
	backup := home + "/.claude/backups/.claude.json.backup.1793182042156"
	v = verify("2.1.306", capture(append(replace(0, root, creds, tmp),
		ev(int(time.Second), root, models.FileDelete, creds),
		ev(int(2*time.Second), root, models.FileWrite, backup))...))
	if len(v.UnexplainedHarness) != 2 || len(v.HarnessBookkeeping) != 1 {
		t.Errorf("a delete and a backup: harness %v, bookkeeping %v", v.UnexplainedHarness, v.HarnessBookkeeping)
	}
}

// V-78: the predicate on the raw shapes, as V-58's: the fold's write of
// the file only with the create of an 8-hex temporary by the same process
// at the same time, a rename onto it only after the rename of such a
// temporary by the same process within a second, under the capture's home.
func TestCredentialsBookkeepingJoinsTheRawTemporary(t *testing.T) {
	const (
		home  = "/home/u"
		creds = home + "/.claude/.credentials.json"
		tmp   = creds + ".tmp.96db3cfb"
	)
	ts := time.Date(2026, 10, 27, 10, 6, 18, 0, time.UTC)
	ev := func(ms int, pid uint32, typ models.ActionType, target string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: ts.Add(time.Duration(ms) * time.Millisecond), ActionType: typ, Target: target, PID: pid}
	}
	raw := models.GroundTruth{ev(0, 7, models.FileWrite, tmp), ev(5, 7, models.FileRename, tmp)}
	bk := Adapter{}.CaptureBookkeeping("2.1.306", home, raw)
	if bk == nil {
		t.Fatal("no declaration")
	}
	for _, c := range []struct {
		e    models.GroundTruthEvent
		want bool
	}{
		{ev(0, 7, models.FileWrite, creds), true},
		{ev(1, 7, models.FileWrite, creds), false},
		{ev(0, 8, models.FileWrite, creds), false},
		{ev(5, 7, models.FileRename, creds), true},
		{ev(1006, 7, models.FileRename, creds), false},
		{ev(0, 7, models.FileOpen, creds), false},
		{ev(0, 7, models.FileDelete, creds), false},
		{ev(0, 7, models.FileClose, tmp), true},
		{ev(0, 7, models.FileDelete, tmp), false},
		{ev(0, 7, models.FileWrite, "/home/v/.claude/.credentials.json"), false},
		{ev(0, 7, models.FileWrite, creds+".tmp.4242.0123456789ab"), false},
	} {
		if got := bk(c.e); got != c.want {
			t.Errorf("%s %s pid %d at %v: %v, want %v", c.e.ActionType, c.e.Target, c.e.PID, c.e.Timestamp.Sub(ts), got, c.want)
		}
	}
	if (Adapter{}).CaptureBookkeeping("2.1.296", home, raw) != nil {
		t.Error("a declaration for a version without the gate")
	}
}

// credentialNotGated are configured versions without V-78's declaration,
// each with why.
var credentialNotGated = map[string]string{
	"2.1.286": "none of its captures renews the token, so its write shape was not measured",
	"2.1.296": "none of its captures renews the token, so its write shape was not measured",
}

// TestCredentialGateAgreesWithTheConfig ties V-78's gate to
// config/agents.json (I-57), as TestCatalogGateAgreesWithTheConfig does
// V-58's.
func TestCredentialGateAgreesWithTheConfig(t *testing.T) {
	c, err := config.Load(filepath.Join("..", "..", "..", config.RelPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range c.Versions(Name) {
		_, gated := credentialVersions[v]
		if _, skip := credentialNotGated[v]; !gated && !skip {
			t.Errorf("configured version %s is not in credentialVersions (V-78): measure its token renewal before configuring it, or explain it", v)
		}
	}
	for v := range credentialVersions {
		if !c.Configured(Name, v) {
			t.Errorf("credentialVersions has %s, which is not configured", v)
		}
	}
}
