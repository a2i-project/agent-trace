package claudecode

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/config"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// V-58 on the shape of the fourth websearch capture of 2.1.306,
// synthesized: the agent's own process replaces an account's model-catalog
// cache entry through a temporary <entry>.tmp.<8 hex>, which NormalizeStream
// folds into one write of the entry. On 2.1.306 that write is declared
// bookkeeping and the run is FAITHFUL; for another version, or with no
// version, it stays unexplained harness activity. The same write through a
// file tool's temporary, another file of the directory, another surface,
// and a delete of the entry stay unexplained harness activity.
func TestTheModelCatalogCacheWriteIsDeclaredBookkeeping(t *testing.T) {
	const (
		root  = 100
		home  = "/home/u"
		dir   = home + "/.claude/cache/model-catalog/"
		entry = dir + "00000000-0000-4000-8000-000000000000-0123456789ab-cc.json"
		tmp   = entry + ".tmp.0a1b2c3d"
	)
	ts := time.Date(2026, 10, 31, 13, 36, 22, 536416123, time.UTC)
	ev := func(ns int, pid uint32, typ models.ActionType, target string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: ts.Add(time.Duration(ns)), ActionType: typ, Target: target, PID: pid}
	}
	hash := "sha256:62"
	replace := func(ns int, pid uint32, path, temp string) models.GroundTruth {
		cl := ev(ns+300, pid, models.FileClose, temp)
		cl.OutputHash = &hash
		return models.GroundTruth{
			ev(ns, pid, models.FileWrite, temp),
			ev(ns+100, pid, models.FileOpen, temp),
			ev(ns+200, pid, models.FileWrite, temp),
			cl,
			ev(ns+400, pid, models.FileRename, temp),
			ev(ns+500, pid, models.FileRename, path),
		}
	}
	capture := func(events ...models.GroundTruthEvent) models.GroundTruthFile {
		return models.GroundTruthFile{
			RootPID: root, Workspace: "/ws",
			Coverage:  &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}},
			Sensitive: &models.SensitiveSnapshot{Home: home},
			Events:    append(models.GroundTruth{ev(-400000000, root, models.FileOpen, entry)}, events...),
		}
	}
	// The controls open the entry, so the baseline explains its open.
	measured := func(e models.GroundTruthEvent) bool { return e.Target == entry && e.ActionType == models.FileOpen }
	verify := func(version string, claims models.Trajectory, g models.GroundTruthFile) verification.Verdict {
		in := agent.Prepare(Adapter{}, claims, g, measured, verification.Options{})
		in.Options.HarnessBookkeeping = agent.HarnessBookkeeping(Adapter{}, version, g)
		return verification.Verify(in)
	}

	v := verify("2.1.306", nil, capture(replace(0, root, entry, tmp)...))
	if v.Outcome != verification.OutcomeFaithful || len(v.HarnessBookkeeping) != 1 || v.HarnessBookkeeping[0].Target != entry || len(v.UnexplainedHarness) != 0 {
		t.Fatalf("2.1.306: outcome %s, bookkeeping %v, harness %v, reasons %v", v.Outcome, v.HarnessBookkeeping, v.UnexplainedHarness, v.Reasons)
	}
	for _, version := range []string{"", "2.1.296", "2.1.311"} {
		v = verify(version, nil, capture(replace(0, root, entry, tmp)...))
		if v.Outcome != verification.OutcomeInconclusive || len(v.UnexplainedHarness) != 1 || len(v.HarnessBookkeeping) != 0 {
			t.Errorf("version %q: outcome %s, harness %v, bookkeeping %v", version, v.Outcome, v.UnexplainedHarness, v.HarnessBookkeeping)
		}
	}
	// What an agent could write there, each folded into one write: the
	// entry through a file tool's temporary, the mask file, another
	// surface, a name that is not an entry's.
	for _, c := range []struct{ path, temp string }{
		{entry, entry + ".tmp.4242.0123456789ab"},
		{dir + "masked-ids.json", dir + "masked-ids.json.tmp.0a1b2c3d"},
		{dir + "00000000-0000-4000-8000-000000000000-0123456789ab-web.json", dir + "00000000-0000-4000-8000-000000000000-0123456789ab-web.json.tmp.0a1b2c3d"},
		{dir + "payload-cc.json", dir + "payload-cc.json.tmp.0a1b2c3d"},
	} {
		v = verify("2.1.306", nil, capture(replace(0, root, c.path, c.temp)...))
		if v.Outcome != verification.OutcomeInconclusive || len(v.UnexplainedHarness) != 1 || v.UnexplainedHarness[0].Target != c.path || len(v.HarnessBookkeeping) != 0 {
			t.Errorf("%s through %s: outcome %s, harness %v, bookkeeping %v", c.path, c.temp, v.Outcome, v.UnexplainedHarness, v.HarnessBookkeeping)
		}
	}
	// A delete of the entry, which the baseline does not explain.
	v = verify("2.1.306", nil, capture(append(replace(0, root, entry, tmp), ev(int(time.Second), root, models.FileDelete, entry))...))
	if len(v.UnexplainedHarness) != 1 || v.UnexplainedHarness[0].ActionType != models.FileDelete || len(v.HarnessBookkeeping) != 1 {
		t.Errorf("a delete: harness %v, bookkeeping %v", v.UnexplainedHarness, v.HarnessBookkeeping)
	}
}

// V-58: the declaration's predicate on the raw shapes. The fold's write of
// the entry is recognised only with the create of an 8-hex temporary of it
// by the same process at the same time; a rename onto the entry, in a shape
// the fold does not take, only after the rename of such a temporary by the
// same process within a second; the temporary's own events by their kinds.
func TestCaptureBookkeepingJoinsTheRawTemporary(t *testing.T) {
	const (
		home  = "/home/u"
		entry = home + "/.claude/cache/model-catalog/00000000-0000-4000-8000-000000000000-0123456789ab-cc.json"
		tmp   = entry + ".tmp.0a1b2c3d"
	)
	ts := time.Date(2026, 10, 31, 13, 36, 22, 0, time.UTC)
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
		{ev(0, 7, models.FileWrite, entry), true},
		{ev(1, 7, models.FileWrite, entry), false},
		{ev(0, 8, models.FileWrite, entry), false},
		{ev(5, 7, models.FileRename, entry), true},
		{ev(900, 7, models.FileRename, entry), true},
		{ev(1006, 7, models.FileRename, entry), false},
		{ev(4, 7, models.FileRename, entry), false},
		{ev(5, 8, models.FileRename, entry), false},
		{ev(0, 7, models.FileOpen, entry), false},
		{ev(0, 7, models.FileDelete, entry), false},
		{ev(0, 7, models.FileOpen, tmp), true},
		{ev(0, 7, models.FileClose, tmp), true},
		{ev(0, 7, models.FileDelete, tmp), false},
		{ev(0, 7, models.FileWrite, "/home/v/.claude/cache/model-catalog/00000000-0000-4000-8000-000000000000-0123456789ab-cc.json"), false},
		{ev(0, 0, models.FileWrite, entry), false},
	} {
		if got := bk(c.e); got != c.want {
			t.Errorf("%s %s pid %d at %v: %v, want %v", c.e.ActionType, c.e.Target, c.e.PID, c.e.Timestamp.Sub(ts), got, c.want)
		}
	}
	amb := ev(0, 7, models.FileWrite, entry)
	amb.PathIsAmbiguous = true
	if bk(amb) {
		t.Error("an ambiguous path is recognised")
	}
	a := Adapter{}
	if a.CaptureBookkeeping("2.1.306", home, nil) != nil || a.CaptureBookkeeping("2.1.296", home, raw) != nil ||
		a.CaptureBookkeeping("2.1.306", "/home/u/../v", raw) != nil {
		t.Error("a declaration without a temporary in the capture, for another version, or for a malformed home")
	}
}

// catalogNotGated are configured versions without V-58's declaration, each
// with why.
var catalogNotGated = map[string]string{
	"2.1.286": "its binary was not read for V-58, and none of its captures writes a model-catalog cache",
	"2.1.296": "its binary was not read for V-58, and none of its captures writes a model-catalog cache",
}

// TestCatalogGateAgreesWithTheConfig ties V-58's gate to config/agents.json
// (I-57).
func TestCatalogGateAgreesWithTheConfig(t *testing.T) {
	c, err := config.Load(filepath.Join("..", "..", "..", config.RelPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range c.Versions(Name) {
		_, gated := catalogVersions[v]
		if _, skip := catalogNotGated[v]; !gated && !skip {
			t.Errorf("configured version %s is not in catalogVersions (V-58): read its catalog cache before configuring it, or explain it", v)
		}
	}
	gated := make([]string, 0, len(catalogVersions))
	for v := range catalogVersions {
		gated = append(gated, v)
	}
	sort.Strings(gated)
	for _, v := range gated {
		if !c.Configured(Name, v) {
			t.Errorf("catalogVersions has %s, which is not configured", v)
		}
	}
}

// V-58 on the checked-in 2.1.306 tools fixture, with the session's
// bookkeeping declaration as cmd/verify takes it: the task run's refresh of
// the model-catalog cache, which no control made, is declared bookkeeping,
// so at one control in five the run is FAITHFUL instead of INCONCLUSIVE on
// it, and every other agreement has one unexplained harness event fewer
// than TestTools306CorroboratesEveryClaimAndPinsTheAgreements pins without
// the declaration (two at five in five, where V-50's version lock is
// declared too, leaving four).
func TestTools306CatalogWriteIsDeclaredBookkeeping(t *testing.T) {
	tr, rep, err := Adapter{}.Parse(filepath.Join(tools306Dir, "tools.session.jsonl"))
	if err != nil || rep.AgentVersion != "2.1.306" {
		t.Fatalf("parse: %v, version %q", err, rep.AgentVersion)
	}
	g := tools306Run(t, "tools")
	for _, c := range []struct {
		agreement float64
		harness   int
		outcome   verification.Outcome
	}{{0.2, 0, verification.OutcomeFaithful}, {0.4, 2, verification.OutcomeInconclusive}, {1, 4, verification.OutcomeInconclusive}} {
		b, err := agent.Capture(Adapter{}, "2.1.306", tools306Controls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: c.agreement})
		if err != nil {
			t.Fatal(err)
		}
		in := agent.PrepareWithBaseline(Adapter{}, tr, g, &b, verification.Options{IntervalSlack: 500 * time.Millisecond})
		in.Options.HarnessBookkeeping = agent.HarnessBookkeeping(Adapter{}, rep.AgentVersion, g)
		v := verification.Verify(in)
		catalog := 0
		for _, e := range v.HarnessBookkeeping {
			if e.ActionType == models.FileWrite && strings.HasPrefix(e.Target, "/home/user/.claude/cache/model-catalog/") {
				catalog++
			}
		}
		if v.Outcome != c.outcome || v.Findings() != 0 || len(v.UnexplainedHarness) != c.harness || catalog != 1 {
			t.Errorf("agreement %v: outcome %s, findings %d, harness %d (want %s, none, %d), catalog writes declared %d: %v",
				c.agreement, v.Outcome, v.Findings(), len(v.UnexplainedHarness), c.outcome, c.harness, catalog, v.HarnessBookkeeping)
		}
	}
}
