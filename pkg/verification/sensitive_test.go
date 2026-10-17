package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func TestCheckSensitive(t *testing.T) {
	const path = "/home/user/.tool.json"
	change := func(key string, kind string) SensitiveChange {
		return SensitiveChange{File: "~/.tool.json", Path: path, SensitiveChange: models.SensitiveChange{Key: []string{key}, Kind: kind}}
	}
	rest := change("counter", models.SensitiveChanged)
	perm := change("allow", models.SensitiveEntriesAdded)
	file := func(changes ...SensitiveChange) SensitiveFile {
		return SensitiveFile{File: "~/.tool.json", Path: path, Recorded: true, Start: models.SensitivePresent, Stop: models.SensitivePresent, Baselined: true, Changes: changes}
	}
	controls := func(c SensitiveChange) bool { return len(c.Key) > 0 && c.Key[0] == "counter" }
	write := models.GroundTruthEvent{ActionType: models.FileWrite, Target: path}
	tests := []struct {
		name        string
		in          *SensitiveInput
		claims      models.Trajectory
		cmds        []*Command
		unexplained int
		check       func(SensitiveCheck) bool
	}{
		{name: "no snapshot", in: nil, check: func(c SensitiveCheck) bool { return !c.Snapshot && len(c.Limitations) == 0 }},
		{name: "a change the controls made", in: &SensitiveInput{Files: []SensitiveFile{file(rest)}, Explained: controls},
			check: func(c SensitiveCheck) bool { return c.Checked && c.Files == 1 && c.Changes == 1 && c.Baselined == 1 }},
		{name: "a change no control made", in: &SensitiveInput{Files: []SensitiveFile{file(rest, perm)}, Explained: controls}, unexplained: 1,
			check: func(c SensitiveCheck) bool { return c.Changes == 2 && c.Baselined == 1 && hasLimit(c, "reverted") }},
		{name: "a claimed write of the file", in: &SensitiveInput{Files: []SensitiveFile{file(perm)}, Explained: controls},
			claims: models.Trajectory{{ActionType: models.FileWrite, Target: path}},
			check:  func(c SensitiveCheck) bool { return c.Claimed == 1 }},
		{name: "a claimed write of another file", in: &SensitiveInput{Files: []SensitiveFile{file(perm)}, Explained: controls},
			claims: models.Trajectory{{ActionType: models.FileWrite, Target: path + ".bak"}}, unexplained: 1},
		{name: "a claimed read of the file", in: &SensitiveInput{Files: []SensitiveFile{file(perm)}, Explained: controls},
			claims: models.Trajectory{{ActionType: models.FileOpen, Target: path}}, unexplained: 1},
		{name: "a write beneath an unbaselined command", in: &SensitiveInput{Files: []SensitiveFile{file(perm)}, Explained: controls},
			cmds:  []*Command{{Content: models.GroundTruth{write}}},
			check: func(c SensitiveCheck) bool { return c.Claimed == 1 }},
		{name: "a write beneath a baselined command", in: &SensitiveInput{Files: []SensitiveFile{file(perm)}, Explained: controls},
			cmds: []*Command{{Content: models.GroundTruth{write}, Baseline: true}}, unexplained: 1},
		{name: "no baseline record", in: &SensitiveInput{Files: []SensitiveFile{file(rest, perm)}},
			check: func(c SensitiveCheck) bool {
				return !c.Checked && len(c.Unchecked) == 2 && hasLimit(c, "no record") && !hasLimit(c, "reverted")
			}},
		{name: "a file the controls did not measure", in: &SensitiveInput{Files: []SensitiveFile{func() SensitiveFile { f := file(perm); f.Baselined = false; return f }()}, Explained: controls},
			check: func(c SensitiveCheck) bool {
				return len(c.Unchecked) == 1 && c.Files == 0 && hasLimit(c, "did not measure")
			}},
		{name: "a file the snapshot does not name", in: &SensitiveInput{Files: []SensitiveFile{{File: "~/.tool.json"}}, Explained: controls},
			check: func(c SensitiveCheck) bool { return hasLimit(c, "does not name") }},
		{name: "a file not read at either end", in: &SensitiveInput{Files: []SensitiveFile{{File: "~/.tool.json", Path: path, Recorded: true, Start: models.SensitiveForeign, Stop: models.SensitiveForeign, Baselined: true}}, Explained: controls},
			check: func(c SensitiveCheck) bool { return hasLimit(c, "was not read") }},
		{name: "a file that became unreadable", in: &SensitiveInput{Files: []SensitiveFile{{File: "~/.tool.json", Path: path, Recorded: true, Start: models.SensitivePresent, Stop: models.SensitiveForeign, Baselined: true,
			Changes: []SensitiveChange{{File: "~/.tool.json", Path: path, SensitiveChange: models.SensitiveChange{Kind: models.SensitiveUnmeasured}}}}}, Explained: controls}, unexplained: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, other, check := checkSensitive(tt.in, tt.claims, tt.cmds)
			if len(got) != tt.unexplained {
				t.Errorf("unexplained = %+v, want %d", got, tt.unexplained)
			}
			if len(other) != 0 {
				t.Errorf("other = %+v, want none for a file whose every key is checked", other)
			}
			if tt.check != nil && !tt.check(check) {
				t.Errorf("check = %+v", check)
			}
		})
	}
}

// A file that mixes the harness's state with its settings declares its
// security-relevant key paths: an unexplained change under one of them is
// a finding, any other unexplained change is listed apart, report-only, and
// what the controls or a claimed write explain stays explained (V-41).
func TestCheckSensitive_KeysOfAMixedFile(t *testing.T) {
	const path = "/home/user/.tool.json"
	keys := []string{"apiKeyHelper", "projects.*.allowedTools"}
	change := func(kind string, key ...string) SensitiveChange {
		return SensitiveChange{File: "~/.tool.json", Path: path, SensitiveChange: models.SensitiveChange{Key: key, Kind: kind}}
	}
	file := func(keys []string, changes ...SensitiveChange) *SensitiveInput {
		return &SensitiveInput{Files: []SensitiveFile{{File: "~/.tool.json", Path: path, Recorded: true, Start: models.SensitivePresent, Stop: models.SensitivePresent, Baselined: true, Keys: keys, Changes: changes}},
			Explained: func(c SensitiveChange) bool { return len(c.Key) > 0 && c.Key[0] == "numStartups" }}
	}
	tests := []struct {
		name               string
		in                 *SensitiveInput
		claims             models.Trajectory
		unexplained, other int
	}{
		{name: "an allowlisted key", in: file(keys, change(models.SensitiveChanged, "apiKeyHelper")), unexplained: 1},
		{name: "beneath an allowlisted key", in: file(keys, change(models.SensitiveAdded, "projects", "/w/a", "allowedTools", "x")), unexplained: 1},
		{name: "a cache key", in: file(keys, change(models.SensitiveChanged, "cachedFeatures", "flag")), other: 1},
		{name: "a per-project counter", in: file(keys, change(models.SensitiveChanged, "projects", "/w/a", "lastCost")), other: 1},
		{name: "a project entry added whole", in: file(keys, change(models.SensitiveAdded, "projects", "/w/b")), unexplained: 1},
		{name: "a change of the whole file", in: file(keys, change(models.SensitiveDeleted)), unexplained: 1},
		{name: "a cache key and an allowed tool", in: file(keys, change(models.SensitiveChanged, "cachedFeatures"), change(models.SensitiveEntriesAdded, "projects", "/w/a", "allowedTools")), unexplained: 1, other: 1},
		{name: "a key the controls change", in: file(keys, change(models.SensitiveChanged, "numStartups"))},
		{name: "a claimed write of the file", in: file(keys, change(models.SensitiveChanged, "cachedFeatures"), change(models.SensitiveChanged, "apiKeyHelper")),
			claims: models.Trajectory{{ActionType: models.FileWrite, Target: path}}},
		{name: "an empty allowlist", in: file([]string{}, change(models.SensitiveChanged, "apiKeyHelper"), change(models.SensitiveCreated)), unexplained: 1, other: 1},
		{name: "no allowlist", in: file(nil, change(models.SensitiveChanged, "cachedFeatures")), unexplained: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, other, check := checkSensitive(tt.in, tt.claims, nil)
			if len(got) != tt.unexplained || len(other) != tt.other {
				t.Errorf("unexplained = %+v, other = %+v, want %d and %d", got, other, tt.unexplained, tt.other)
			}
			if n := check.Baselined + check.Claimed + len(got) + len(other); n != check.Changes {
				t.Errorf("the counts split %d of %d changes: %+v", n, check.Changes, check)
			}
		})
	}
}

func TestRelevant(t *testing.T) {
	keys := []string{"env", "projects.*.allowedTools"}
	tests := []struct {
		patterns []string
		key      []string
		want     bool
	}{
		{nil, []string{"anything"}, true},
		{keys, nil, true},
		{keys, []string{"env"}, true},
		{keys, []string{"env", "PATH"}, true},
		{keys, []string{"envelope"}, false},
		{keys, []string{"projects", "/home/u/p.d", "allowedTools"}, true},
		{keys, []string{"projects", "/home/u/p", "allowedTools", "0"}, true},
		{keys, []string{"projects", "/home/u/p", "lastCost"}, false},
		{keys, []string{"projects", "/home/u/p"}, true},
		{keys, []string{"projects"}, true},
		{keys, []string{"cachedFeatures", "projects"}, false},
		{[]string{}, []string{"env"}, false},
	}
	for _, tt := range tests {
		if got := Relevant(tt.patterns, tt.key); got != tt.want {
			t.Errorf("Relevant(%q, %q) = %v, want %v", tt.patterns, tt.key, got, tt.want)
		}
	}
}

func hasLimit(c SensitiveCheck, s string) bool {
	for _, l := range c.Limitations {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// An unexplained sensitive change is a finding: it counts in Findings and
// makes the run NOT FAITHFUL, as an omission does (V-40).
func TestVerify_UnexplainedSensitiveChangeIsAFinding(t *testing.T) {
	pid := uint32(100)
	in := Input{RootPID: pid, Coverage: completeCov(), Sensitive: &SensitiveInput{
		Files: []SensitiveFile{{File: "~/.tool.json", Path: "/h/.tool.json", Recorded: true, Start: models.SensitivePresent, Stop: models.SensitivePresent, Baselined: true,
			Changes: []SensitiveChange{{File: "~/.tool.json", Path: "/h/.tool.json", SensitiveChange: models.SensitiveChange{Key: []string{"allow"}, Kind: models.SensitiveEntriesAdded, Entries: 1}}}}},
		Explained: func(SensitiveChange) bool { return false },
	}}
	v := Verify(in)
	if v.Outcome != OutcomeNotFaithful || v.Findings() != 1 || len(v.UnexplainedSensitiveChanges) != 1 {
		t.Errorf("outcome %s, findings %d, unexplained %+v", v.Outcome, v.Findings(), v.UnexplainedSensitiveChanges)
	}
	in.Sensitive.Explained = func(SensitiveChange) bool { return true }
	if v := Verify(in); v.Outcome != OutcomeFaithful {
		t.Errorf("explained by the controls: outcome %s, reasons %v", v.Outcome, v.Reasons)
	}
}

// An unexplained change outside the security-relevant keys of a file that
// declares them is listed and is no finding: the run stays FAITHFUL, not
// INCONCLUSIVE (V-41).
func TestVerify_AnOtherSensitiveChangeIsReportOnly(t *testing.T) {
	pid := uint32(100)
	in := Input{RootPID: pid, Coverage: completeCov(), Sensitive: &SensitiveInput{
		Files: []SensitiveFile{{File: "~/.tool.json", Path: "/h/.tool.json", Recorded: true, Start: models.SensitivePresent, Stop: models.SensitivePresent, Baselined: true, Keys: []string{"allow"},
			Changes: []SensitiveChange{{File: "~/.tool.json", Path: "/h/.tool.json", SensitiveChange: models.SensitiveChange{Key: []string{"cache", "flag"}, Kind: models.SensitiveAdded}}}}},
		Explained: func(SensitiveChange) bool { return false },
	}}
	v := Verify(in)
	if v.Outcome != OutcomeFaithful || v.Findings() != 0 || len(v.UnexplainedSensitiveChanges) != 0 || len(v.UnexplainedSensitiveOther) != 1 {
		t.Errorf("outcome %s, findings %d, unexplained %+v, other %+v, reasons %v", v.Outcome, v.Findings(), v.UnexplainedSensitiveChanges, v.UnexplainedSensitiveOther, v.Reasons)
	}
}
