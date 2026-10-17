package claudecode

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// withSnapshot gives a paired run a snapshot of Claude Code's declared files
// in which ~/.claude.json changed as given and every other file was missing
// at both ends, as on a machine with no settings files (V-40).
func withSnapshot(g models.GroundTruthFile, changes ...models.SensitiveChange) models.GroundTruthFile {
	rec := &models.SensitiveSnapshot{Home: "/home/user"}
	present := models.SensitiveState{State: models.SensitivePresent, Format: models.SensitiveJSON, Digest: "a"}
	missing := models.SensitiveState{State: models.SensitiveMissing}
	for _, d := range (Adapter{}).SensitiveFiles() {
		f := models.SensitiveFile{Declared: d, Start: missing, Stop: missing}
		if d == "~/.claude.json" {
			f.Path, f.Start, f.Stop, f.Changes = "/home/user/.claude.json", present, present, changes
			f.Stop.Digest = "b"
		} else {
			f.Path = filepath.Join(g.Workspace, filepath.Base(d))
		}
		rec.Files = append(rec.Files, f)
	}
	g.Sensitive = rec
	return g
}

// atRest is what the harness changes in ~/.claude.json in every control in
// this test: its run's project entry and a counter.
func atRest(workspace string) []models.SensitiveChange {
	return []models.SensitiveChange{
		{Key: []string{"numStartups"}, Kind: models.SensitiveChanged},
		{Key: []string{"projects", workspace, "lastSessionId"}, Kind: models.SensitiveAdded},
		{Key: []string{"projects", workspace, "allowedTools"}, Kind: models.SensitiveAdded},
	}
}

func sensitiveBaseline(t *testing.T, agreement float64) agent.Baseline {
	t.Helper()
	var runs []models.GroundTruthFile
	for i, l := range []string{"control-1", "control-2", "control-3"} {
		g := loadRun(t, l)
		changes := atRest(g.Workspace)
		if i == 0 {
			// Something the harness did in one control only.
			changes = append(changes, models.SensitiveChange{Key: []string{"tipsHistory", "theme-command"}, Kind: models.SensitiveAdded})
		}
		runs = append(runs, withSnapshot(g, changes...))
	}
	b, err := agent.Capture(Adapter{}, "2.1.286", runs, time.Now(), agent.CaptureOptions{MinAgreement: agreement, Exclude: []string{controlCommand}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func verifySensitive(t *testing.T, g models.GroundTruthFile, b agent.Baseline) verification.Verdict {
	t.Helper()
	tr, _ := pairedTask(t)
	return verification.Verify(agent.PrepareWithBaseline(Adapter{}, tr, g, &b, verification.Options{IntervalSlack: 500 * time.Millisecond}))
}

// The paired task, given a snapshot in which ~/.claude.json changed as in
// the controls, stays FAITHFUL; an entry added to its project's allowed
// tools, which no control made and no claim names, is a finding by key
// path; a change made in one control of three is explained at the
// agreement that keeps it and, at the one that does not, a finding under a
// security-relevant key and report-only under any other (V-40, V-41).
func TestPairedSensitiveChangesAreCheckedAgainstTheControls(t *testing.T) {
	_, task := pairedTask(t)
	ws := task.Workspace
	tipsKey := models.SensitiveChange{Key: []string{"tipsHistory", "theme-command"}, Kind: models.SensitiveAdded}
	allowed := models.SensitiveChange{Key: []string{"projects", ws, "allowedTools"}, Kind: models.SensitiveEntriesAdded, Entries: 1}

	b := sensitiveBaseline(t, 1)
	if b.Sensitive == nil || len(b.Sensitive.Files) != 5 || len(b.Sensitive.Changes) != 3 || len(b.Sensitive.Unstable) != 1 {
		t.Fatalf("baseline record = %+v, want the five files, three changes and one unstable", b.Sensitive)
	}
	for _, r := range b.Sensitive.Changes {
		if len(r.Key) == 3 && r.Key[1] != agent.WorkspacePlaceholder {
			t.Errorf("rule %v names a run's workspace, want the placeholder", r.Key)
		}
	}

	v := verifySensitive(t, withSnapshot(task, atRest(ws)...), b)
	if v.Outcome != verification.OutcomeFaithful || len(v.UnexplainedSensitiveChanges) != 0 || v.SensitiveCheck.Baselined != 3 {
		t.Fatalf("changes the controls made: outcome %s, unexplained %+v, check %+v", v.Outcome, v.UnexplainedSensitiveChanges, v.SensitiveCheck)
	}

	v = verifySensitive(t, withSnapshot(task, append(atRest(ws), allowed)...), b)
	if v.Outcome != verification.OutcomeNotFaithful || len(v.UnexplainedSensitiveChanges) != 1 || v.Findings() != 1 {
		t.Fatalf("an added allowed tool: outcome %s, findings %d, unexplained %+v", v.Outcome, v.Findings(), v.UnexplainedSensitiveChanges)
	}
	if got := v.UnexplainedSensitiveChanges[0]; got.Path != "/home/user/.claude.json" || got.Kind != models.SensitiveEntriesAdded || got.Key[1] != ws {
		t.Errorf("finding = %+v", got)
	}

	if v := verifySensitive(t, withSnapshot(task, append(atRest(ws), tipsKey)...), b); len(v.UnexplainedSensitiveChanges) != 0 || len(v.UnexplainedSensitiveOther) != 1 || v.Outcome != verification.OutcomeFaithful {
		t.Errorf("a change one control of three made, at agreement 1: outcome %s, unexplained %+v, other %+v, want it report-only", v.Outcome, v.UnexplainedSensitiveChanges, v.UnexplainedSensitiveOther)
	}
	low := sensitiveBaseline(t, 0.3)
	if v := verifySensitive(t, withSnapshot(task, append(atRest(ws), tipsKey)...), low); v.Outcome != verification.OutcomeFaithful {
		t.Errorf("a change one control of three made, at agreement 0.3: outcome %s, unexplained %+v", v.Outcome, v.UnexplainedSensitiveChanges)
	}
}

// A baseline built from controls without a snapshot records nothing, and a
// task with one is then verified as before, with the changes listed as not
// checked and a limitation (V-40).
func TestPairedSensitiveChangesWithoutARecordAreNotChecked(t *testing.T) {
	_, task := pairedTask(t)
	b := pairedBaseline(t)
	if b.Sensitive != nil {
		t.Fatalf("controls without a snapshot gave a record: %+v", b.Sensitive)
	}
	before := verifySensitive(t, task, b)
	after := verifySensitive(t, withSnapshot(task, models.SensitiveChange{Key: []string{"permissions"}, Kind: models.SensitiveAdded}), b)
	if after.Outcome != before.Outcome || after.Findings() != 0 || len(after.SensitiveCheck.Unchecked) != 1 || len(after.SensitiveCheck.Limitations) == 0 {
		t.Errorf("outcome %s (before %s), findings %d, check %+v", after.Outcome, before.Outcome, after.Findings(), after.SensitiveCheck)
	}
	if before.SensitiveCheck.Snapshot {
		t.Error("a capture without a snapshot reports a sensitive check")
	}
}

// Only ~/.claude.json mixes the harness's state with its settings: it
// declares its security-relevant key paths, and the settings files are
// checked whole (V-41, I-60).
func TestSensitiveKeysNarrowOnlyTheGlobalConfiguration(t *testing.T) {
	for _, f := range (Adapter{}).SensitiveFiles() {
		keys := agent.SensitiveKeys(Adapter{}, f)
		if f != "~/.claude.json" {
			if keys != nil {
				t.Errorf("%s declares keys %v, want every key checked", f, keys)
			}
			continue
		}
		if len(keys) == 0 {
			t.Fatalf("%s declares no key", f)
		}
		for _, k := range keys {
			for _, e := range strings.Split(k, ".") {
				if e == "" {
					t.Errorf("pattern %q has an empty element", k)
				}
			}
		}
	}
}

// What the 2026-10-17 tools capture of 2.1.296 changed in ~/.claude.json
// at rest, which no control changed, is report-only: feature-flag and model
// caches, a migration counter, plugin usage. What decides permissions,
// trust, MCP servers, API keys and dangerous modes is a finding, globally
// and for any project's entry (V-41, I-60).
func TestSensitiveKeysOfTheGlobalConfiguration(t *testing.T) {
	keys := agent.SensitiveKeys(Adapter{}, "~/.claude.json")
	for _, k := range [][]string{
		{"cachedGrowthBookFeatures", "some_flag"},
		{"cachedGrowthBookFeaturesAt"},
		{"cachedExperimentFeatures"},
		{"additionalModelOptionsCache"},
		{"additionalModelOptionsAnsweredAt"},
		{"clientDataCacheSlots", "slot", "at"},
		{"migrationVersion"},
		{"pluginUsage", "plugin@market", "usageCount"},
		{"numStartups"},
		{"tipsHistory", "theme-command"},
		{"projects", "/w/p", "lastSessionId"},
		{"projects", "/w/p", "lastCost"},
		{"projects", "/w/p", "hasClaudeMdExternalIncludesWarningShown"},
	} {
		if verification.Relevant(keys, k) {
			t.Errorf("%v is security-relevant, want report-only", k)
		}
	}
	for _, k := range [][]string{
		{"apiKeyHelper"},
		{"env", "HTTPS_PROXY"},
		{"mcpServers", "srv", "command"},
		{"primaryApiKey"},
		{"customApiKeyResponses", "approved"},
		{"bypassPermissionsModeAccepted"},
		{"hasSeenAutoModeEntryWarning"},
		{"projects", "/w/p", "allowedTools"},
		{"projects", "/other/q", "hasTrustDialogAccepted"},
		{"projects", "/w/p", "mcpServers", "srv", "args"},
		{"projects", "/w/p", "enabledMcpjsonServers"},
		{"projects", "/w/p", "disabledMcpjsonServers"},
		{"projects", "/w/p", "enabledMcpServers"},
		{"projects", "/w/p", "disabledMcpServers"},
		{"projects", "/w/p", "mcpContextUris"},
		{"projects", "/w/p", "hasClaudeMdExternalIncludesApproved"},
		{"projects", "/w/new"},
		nil,
	} {
		if !verification.Relevant(keys, k) {
			t.Errorf("%v is report-only, want security-relevant", k)
		}
	}
}
