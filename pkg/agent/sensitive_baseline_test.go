package agent

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

type declaring struct{ fake }

func (declaring) SensitiveFiles() []string { return []string{"~/.a.json", "~/.b.json"} }

func snapRun(ws string, a, b models.SensitiveState, changes ...models.SensitiveChange) models.GroundTruthFile {
	return models.GroundTruthFile{RootPID: 1, Workspace: ws, Coverage: &models.Coverage{Schema: models.CoverageSchema}, Sensitive: &models.SensitiveSnapshot{Home: "/h", Files: []models.SensitiveFile{
		{Declared: "~/.a.json", Path: "/h/.a.json", Start: a, Stop: a, Changes: changes},
		{Declared: "~/.b.json", Path: "/h/.b.json", Start: b, Stop: b},
	}}}
}

// The baseline records what the controls changed in the declared files at
// the agreement rules use, with the run's workspace templated in a key, and
// only for the files every control measured; none when a control has no
// snapshot (V-40).
func TestCaptureRecordsSensitiveChanges(t *testing.T) {
	present := models.SensitiveState{State: models.SensitivePresent, Format: models.SensitiveJSON}
	foreign := models.SensitiveState{State: models.SensitiveForeign}
	proj := func(ws string) models.SensitiveChange {
		return models.SensitiveChange{Key: []string{"projects", ws, "last"}, Kind: models.SensitiveChanged}
	}
	once := models.SensitiveChange{Key: []string{"tips"}, Kind: models.SensitiveAdded}
	runs := []models.GroundTruthFile{
		snapRun("/w/1", present, present, proj("/w/1"), once),
		snapRun("/w/2", present, foreign, proj("/w/2")),
	}
	a := declaring{fake{name: "d"}}
	b, err := Capture(a, "v", runs, time.Now(), CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := b.Sensitive
	if s == nil || len(s.Files) != 1 || s.Files[0] != "~/.a.json" {
		t.Fatalf("record = %+v, want only the file both controls measured", s)
	}
	if len(s.Changes) != 1 || s.Changes[0].Key[1] != WorkspacePlaceholder || len(s.Unstable) != 1 || s.Unstable[0].Key[0] != "tips" {
		t.Errorf("changes = %+v, unstable = %+v", s.Changes, s.Unstable)
	}
	explained := b.SensitiveExplained("/w/run")
	at := func(c models.SensitiveChange) verification.SensitiveChange {
		return verification.SensitiveChange{File: "~/.a.json", Path: "/h/.a.json", SensitiveChange: c}
	}
	if !explained(at(proj("/w/run"))) || explained(at(proj("/w/other"))) || explained(at(once)) {
		t.Error("the record does not match the run's workspace exactly, or explains an unstable change")
	}
	low, _ := Capture(a, "v", runs, time.Now(), CaptureOptions{MinAgreement: 0.5})
	if len(low.Sensitive.Changes) != 2 {
		t.Errorf("at half agreement: %+v, want both changes", low.Sensitive.Changes)
	}

	runs = append(runs, models.GroundTruthFile{RootPID: 1, Coverage: &models.Coverage{Schema: models.CoverageSchema}})
	if b, _ := Capture(a, "v", runs, time.Now(), CaptureOptions{}); b.Sensitive != nil {
		t.Errorf("a control without a snapshot left a record: %+v", b.Sensitive)
	}
	if b, _ := Capture(fake{name: "f"}, "v", runs[:2], time.Now(), CaptureOptions{}); b.Sensitive != nil {
		t.Errorf("an adapter that declares nothing has a record: %+v", b.Sensitive)
	}
}
