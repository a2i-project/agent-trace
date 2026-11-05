package gemini

import (
	"path/filepath"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/config"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// V-85, V-93: the renewal and the flag metrics are declared by their exact
// shape for 1.4.7 only. Another path, a query, another method, a POST
// without a body, another host and another version stay checked.
func TestHarnessHousekeepingDeclaresTheRenewalAndTheFlagMetricsOnly(t *testing.T) {
	is := agent.HarnessHousekeeping(Adapter{}, "1.4.7")
	if is == nil {
		t.Fatal("1.4.7 declares nothing")
	}
	body := "sha256:00"
	req := func(target string, withBody bool) models.GroundTruthEvent {
		e := models.GroundTruthEvent{ActionType: models.NetRequest, Target: target}
		if withBody {
			e.RequestHash = &body
		}
		return e
	}
	for _, c := range []struct {
		e    models.GroundTruthEvent
		want bool
	}{
		{models.GroundTruthEvent{ActionType: models.NetConnect, Target: "oauth2.googleapis.com"}, true},
		{req("POST https://oauth2.googleapis.com/token", true), true},
		{req("POST https://oauth2.googleapis.com/token", false), false},
		{req("POST https://oauth2.googleapis.com/token?x=1", true), false},
		{req("POST https://oauth2.googleapis.com/revoke", true), false},
		{req("GET https://oauth2.googleapis.com/token", false), false},
		{req("POST https://oauth2.googleapis.com/device/code", true), false},
		{models.GroundTruthEvent{ActionType: models.NetConnect, Target: "accounts.google.com"}, false},
		{models.GroundTruthEvent{ActionType: models.NetConnect, Target: "oauth2.googleapis.com", TargetTruncated: true}, false},
		{req("POST https://antigravity-unleash.goog/api/client/metrics", true), true},
		{req("POST https://antigravity-unleash.goog/api/client/metrics", false), false},
		{req("POST https://antigravity-unleash.goog/api/client/register", true), false},
		{req("POST https://antigravity-unleash.goog/api/client/metrics?x=1", true), false},
		{req("GET https://antigravity-unleash.goog/api/client/metrics", false), false},
		{models.GroundTruthEvent{ActionType: models.NetConnect, Target: "antigravity-unleash.goog"}, false},
	} {
		if got := is(c.e); got != c.want {
			t.Errorf("%s %s (body %v): %v, want %v", c.e.ActionType, c.e.Target, c.e.RequestHash != nil, got, c.want)
		}
	}
	for _, v := range []string{"", "1.3.4", "1.4.8"} {
		if agent.HarnessHousekeeping(Adapter{}, v) != nil {
			t.Errorf("version %q declares housekeeping", v)
		}
	}
}

// housekeepingNotGated are configured versions without the declaration,
// each with why.
var housekeepingNotGated = map[string]string{
	"1.3.4": "its captures read no request content, so the renewal's request is not measured",
}

// TestHousekeepingGateAgreesWithTheConfig ties the declared versions to
// config/agents.json, as Claude Code's gate is (V-54).
func TestHousekeepingGateAgreesWithTheConfig(t *testing.T) {
	c, err := config.Load(filepath.Join("..", "..", "..", config.RelPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range c.Versions(Name) {
		if _, skip := housekeepingNotGated[v]; !housekeepingVersions[v] && !skip {
			t.Errorf("configured version %s is not in housekeepingVersions (V-85): measure its token renewal, or explain it", v)
		}
	}
	for v := range housekeepingVersions {
		if !c.Configured(Name, v) {
			t.Errorf("housekeepingVersions has %s, which is not configured", v)
		}
	}
}

// V-92: the background-task files of 1.4.7 under a conversation's brain
// directory are declared bookkeeping, each with the kinds the long parity
// run showed; another file, kind, home or version is not.
func TestHarnessBookkeepingDeclaresTheBackgroundTaskFilesOnly(t *testing.T) {
	const id = "0b18d7d3-41b4-4dfe-b649-e8ba776c383a"
	const id2 = "12e4e6e3-5d77-4488-988f-200e0e1f04ac"
	sys := "/home/u/.gemini/antigravity-cli/brain/" + id + "/.system_generated/"
	is := agent.HarnessBookkeeping(Adapter{}, "1.4.7", models.GroundTruthFile{})
	if is == nil {
		t.Fatal("1.4.7 declares nothing")
	}
	f := func(a models.ActionType, p string) models.GroundTruthEvent {
		return models.GroundTruthEvent{ActionType: a, Target: p}
	}
	for _, c := range []struct {
		e    models.GroundTruthEvent
		want bool
	}{
		{f(models.FileOpen, sys+"tasks/task-356.log"), true},
		{f(models.FileWrite, sys+"tasks/task-356.log"), true},
		{f(models.FileClose, sys+"tasks/task-356.log"), true},
		{f(models.FileDelete, sys+"tasks/task-356.log"), false},
		{f(models.FileRename, sys+"tasks/task-356.log"), false},
		{f(models.FileWrite, sys+"tasks/task-x.log"), false},
		{f(models.FileWrite, sys+"messages/."+id+"."+id2+".tmp"), true},
		{f(models.FileRename, sys+"messages/."+id+"."+id2+".tmp"), true},
		{f(models.FileRename, sys+"messages/"+id2+".json"), true},
		{f(models.FileOpen, sys+"messages/"+id2+".json"), true},
		{f(models.FileWrite, sys+"messages/"+id2+".json"), false},
		{f(models.FileWrite, sys+"messages/read.json"), true},
		{f(models.FileDelete, sys+"messages/read.json"), false},
		{f(models.FileWrite, sys+"messages/undelivered/"+id2), true},
		{f(models.FileDelete, sys+"messages/undelivered/"+id2), true},
		{f(models.FileWrite, sys+"messages/other.json"), false},
		{f(models.FileWrite, sys+"logs/transcript.jsonl"), false},
		{f(models.FileWrite, "/home/u/.gemini/antigravity-cli/brain/x/.system_generated/tasks/task-1.log"), false},
		{f(models.FileWrite, "/ws/tasks/task-1.log"), false},
	} {
		if got := is(c.e); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.e.ActionType, c.e.Target, got, c.want)
		}
	}
	for _, v := range []string{"", "1.3.4", "1.4.8"} {
		if agent.HarnessBookkeeping(Adapter{}, v, models.GroundTruthFile{}) != nil {
			t.Errorf("version %q declares bookkeeping", v)
		}
	}
	if b := (Adapter{}).HarnessBookkeeping("1.4.7", "/home/v"); b(f(models.FileWrite, sys+"tasks/task-1.log")) {
		t.Error("another home's task log is declared")
	}
}

// V-94: of the background-task files, 1.4.7 names only the task logs as
// files the harness writes while the agent reads them; another version, a
// message file and another home's log are not named.
func TestHarnessClaimedWritesNamesTheTaskLogsOnly(t *testing.T) {
	const id = "0b18d7d3-41b4-4dfe-b649-e8ba776c383a"
	sys := "/home/u/.gemini/antigravity-cli/brain/" + id + "/.system_generated/"
	is := agent.HarnessClaimedWrites(Adapter{}, "1.4.7", models.GroundTruthFile{})
	if is == nil {
		t.Fatal("1.4.7 declares nothing")
	}
	for p, want := range map[string]bool{
		sys + "tasks/task-441.log":     true,
		sys + "tasks/task-441.log.bak": false,
		sys + "messages/read.json":     false,
		sys + "logs/transcript.jsonl":  false,
		"/ws/tasks/task-441.log":       false,
	} {
		if got := is(p); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
	for _, v := range []string{"", "1.3.4", "1.4.8"} {
		if agent.HarnessClaimedWrites(Adapter{}, v, models.GroundTruthFile{}) != nil {
			t.Errorf("version %q declares claimed-path writes", v)
		}
	}
	if (Adapter{}).HarnessClaimedWrites("1.4.7", "/home/v")(sys + "tasks/task-1.log") {
		t.Error("another home's task log is declared")
	}
}
