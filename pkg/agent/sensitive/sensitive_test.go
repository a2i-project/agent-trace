package sensitive

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func diffOf(t *testing.T, before, after string) []models.SensitiveChange {
	t.Helper()
	return Diff(Summarize([]byte(before), testKey), Summarize([]byte(after), testKey))
}

func TestDiffNamesKeyPathsAndKinds(t *testing.T) {
	ws := "/ws/run"
	tests := []struct {
		name          string
		before, after string
		want          []models.SensitiveChange
	}{
		{"unchanged", `{"a":1,"b":{"c":true}}`, `{"b":{"c":true},"a":1}`, nil},
		{"reformatted only", `{"a": 1}`, "{\n  \"a\": 1\n}\n", nil},
		{"value changed", `{"a":1,"b":{"c":true}}`, `{"a":1,"b":{"c":false}}`,
			[]models.SensitiveChange{{Key: []string{"b", "c"}, Kind: models.SensitiveChanged}}},
		{"number spelled differently", `{"a":1}`, `{"a":1.0}`,
			[]models.SensitiveChange{{Key: []string{"a"}, Kind: models.SensitiveChanged}}},
		{"key added and removed", `{"a":1}`, `{"b":1}`,
			[]models.SensitiveChange{{Key: []string{"a"}, Kind: models.SensitiveRemoved}, {Key: []string{"b"}, Kind: models.SensitiveAdded}}},
		{"per-project key", `{"projects":{}}`, `{"projects":{"` + ws + `":{"allowedTools":[]}}}`,
			[]models.SensitiveChange{
				{Key: []string{"projects"}, Kind: models.SensitiveRemoved},
				{Key: []string{"projects", ws, "allowedTools"}, Kind: models.SensitiveAdded},
			}},
		{"list entry added", `{"permissions":{"allow":["Read"]}}`, `{"permissions":{"allow":["Read","Bash(rm:*)"]}}`,
			[]models.SensitiveChange{{Key: []string{"permissions", "allow"}, Kind: models.SensitiveEntriesAdded, Entries: 1}}},
		{"list entry removed and added", `{"allow":["a","b"]}`, `{"allow":["b","c"]}`,
			[]models.SensitiveChange{{Key: []string{"allow"}, Kind: models.SensitiveEntriesAdded, Entries: 1}, {Key: []string{"allow"}, Kind: models.SensitiveEntriesRemoved, Entries: 1}}},
		{"list reordered is a set", `{"allow":["a","b"]}`, `{"allow":["b","a"]}`, nil},
		{"new list with entries", `{}`, `{"allow":["x"]}`,
			[]models.SensitiveChange{{Key: nil, Kind: models.SensitiveRemoved}, {Key: []string{"allow"}, Kind: models.SensitiveAdded}, {Key: []string{"allow"}, Kind: models.SensitiveEntriesAdded, Entries: 1}}},
		{"list entry object changed", `{"hooks":[{"cmd":"a"}]}`, `{"hooks":[{"cmd":"b"}]}`,
			[]models.SensitiveChange{{Key: []string{"hooks"}, Kind: models.SensitiveEntriesAdded, Entries: 1}, {Key: []string{"hooks"}, Kind: models.SensitiveEntriesRemoved, Entries: 1}}},
		{"list became a value", `{"a":[1]}`, `{"a":1}`,
			[]models.SensitiveChange{{Key: []string{"a"}, Kind: models.SensitiveChanged}}},
		{"not JSON", "line one\n", "line two\n",
			[]models.SensitiveChange{{Kind: models.SensitiveContent}}},
		{"JSON became not JSON", `{"a":1}`, `{"a":1`,
			[]models.SensitiveChange{{Kind: models.SensitiveContent}}},
		{"trailing data is not JSON", `{"a":1} x`, `{"a":1} y`,
			[]models.SensitiveChange{{Kind: models.SensitiveContent}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diffOf(t, tt.before, tt.after)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Diff = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSummaryRecordsNoValue(t *testing.T) {
	s := Summarize([]byte(`{"token":"sk-secret-value","allow":["Bash(curl evil)"]}`), testKey)
	if s.State.Format != models.SensitiveJSON || s.State.State != models.SensitivePresent {
		t.Fatalf("state = %+v", s.State)
	}
	for _, l := range s.leaves {
		for _, v := range append([]string{l.hash}, keysOf(l.entries)...) {
			if strings.Contains(v, "secret") || strings.Contains(v, "curl") {
				t.Errorf("leaf %v holds a value: %q", l.key, v)
			}
		}
	}
	// Another key gives other hashes: without the key a hash cannot be
	// matched against a guessed value.
	other := Summarize([]byte(`{"token":"sk-secret-value"}`), []byte("another key"))
	if other.State.Digest == s.State.Digest || other.leaves[pathKey([]string{"token"})].hash == s.leaves[pathKey([]string{"token"})].hash {
		t.Error("the hashes do not depend on the key")
	}
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestReadStates(t *testing.T) {
	dir := t.TempDir()
	me := os.Getuid()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got := Read(filepath.Join(dir, "absent.json"), me, testKey).State.State; got != models.SensitiveMissing {
		t.Errorf("absent file: %s, want missing", got)
	}
	if got := Read(dir, me, testKey).State.State; got != models.SensitiveNotRegular {
		t.Errorf("directory: %s, want not-regular", got)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Read(fifo, me, testKey).State.State; got != models.SensitiveNotRegular {
		t.Errorf("FIFO: %s, want not-regular, read without blocking", got)
	}
	j := write("s.json", `{"a":1}`)
	if s := Read(j, me, testKey); s.State.State != models.SensitivePresent || s.State.Format != models.SensitiveJSON || s.State.Digest == "" {
		t.Errorf("JSON file: %+v", s.State)
	}
	o := write("s.txt", "plain")
	if s := Read(o, me, testKey); s.State.Format != models.SensitiveOther {
		t.Errorf("text file: %+v", s.State)
	}
	if got := Read(j, me+1, testKey).State.State; got != models.SensitiveForeign {
		t.Errorf("file of another user: %s, want foreign", got)
	}
	if got := Read(j, -1, testKey).State.State; got != models.SensitivePresent {
		t.Errorf("any owner: %s, want present", got)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(j, link); err != nil {
		t.Fatal(err)
	}
	if got := Read(link, me, testKey).State.State; got != models.SensitivePresent {
		t.Errorf("link to the user's own file: %s, want present", got)
	}
}

func TestDiffOfStates(t *testing.T) {
	missing := Summary{State: models.SensitiveState{State: models.SensitiveMissing}}
	foreign := Summary{State: models.SensitiveState{State: models.SensitiveForeign}}
	json := Summarize([]byte(`{"permissions":{"allow":["x"]}}`), testKey)
	text := Summarize([]byte("x"), testKey)
	tests := []struct {
		name        string
		start, stop Summary
		want        []models.SensitiveChange
	}{
		{"missing at both ends", missing, missing, nil},
		{"created JSON lists its keys", missing, json, []models.SensitiveChange{
			{Kind: models.SensitiveCreated},
			{Key: []string{"permissions", "allow"}, Kind: models.SensitiveAdded},
			{Key: []string{"permissions", "allow"}, Kind: models.SensitiveEntriesAdded, Entries: 1},
		}},
		{"created text", missing, text, []models.SensitiveChange{{Kind: models.SensitiveCreated}}},
		{"deleted lists no key", json, missing, []models.SensitiveChange{{Kind: models.SensitiveDeleted}}},
		{"became another user's", json, foreign, []models.SensitiveChange{{Kind: models.SensitiveUnmeasured}}},
		{"another user's at both ends", foreign, foreign, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Diff(tt.start, tt.stop); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Diff = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSnapshotStartStop(t *testing.T) {
	home, ws := t.TempDir(), t.TempDir()
	cfg := filepath.Join(home, ".tool.json")
	if err := os.WriteFile(cfg, []byte(`{"projects":{},"allow":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	declared := []string{"~/.tool.json", "{workspace}/.tool/local.json", "~/.tool.json", "relative.json", "~/../escape.json"}
	s := start(declared, home, ws, os.Getuid(), testKey)
	if err := os.WriteFile(cfg, []byte(`{"projects":{},"allow":["Bash(*)"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, ".tool"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".tool", "local.json"), []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := s.Stop()
	if rec.Home != home || len(rec.Files) != 2 {
		t.Fatalf("record = %+v, want the two resolvable declarations once each", rec)
	}
	if f := rec.Files[0]; f.Declared != "~/.tool.json" || f.Path != cfg ||
		!reflect.DeepEqual(f.Changes, []models.SensitiveChange{{Key: []string{"allow"}, Kind: models.SensitiveEntriesAdded, Entries: 1}}) {
		t.Errorf("home file = %+v", f)
	}
	if f := rec.Files[1]; f.Start.State != models.SensitiveMissing || f.Stop.Format != models.SensitiveOther ||
		!reflect.DeepEqual(f.Changes, []models.SensitiveChange{{Kind: models.SensitiveCreated}}) {
		t.Errorf("workspace file = %+v", f)
	}
	if files, changes := Changed(rec); files != 2 || changes != 2 {
		t.Errorf("Changed = %d, %d, want 2, 2", files, changes)
	}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		declared, home, ws, want string
		ok                       bool
	}{
		{"~/.claude.json", "/home/u", "/w", "/home/u/.claude.json", true},
		{"{workspace}/.claude/settings.json", "/home/u", "/w", "/w/.claude/settings.json", true},
		{"~/.claude.json", "", "/w", "", false},
		{"{workspace}/x", "/home/u", "", "", false},
		{"~/../etc/passwd", "/home/u", "/w", "", false},
		{"/etc/passwd", "/home/u", "/w", "", false},
		{"~/", "/home/u", "/w", "", false},
	}
	for _, tt := range tests {
		got, ok := Resolve(tt.declared, tt.home, tt.ws)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Resolve(%q) = %q, %v, want %q, %v", tt.declared, got, ok, tt.want, tt.ok)
		}
	}
}

func TestFormatKey(t *testing.T) {
	tests := map[string][]string{
		"(file)":                           nil,
		"permissions.allow":                {"permissions", "allow"},
		`projects["/ws/run"].allowedTools`: {"projects", "/ws/run", "allowedTools"},
		`mcpServers["a.b"]`:                {"mcpServers", "a.b"},
		`["1x"].y`:                         {"1x", "y"},
		`tipsHistory.new-user-warmup`:      {"tipsHistory", "new-user-warmup"},
		`a[""]`:                            {"a", ""},
	}
	for want, key := range tests {
		if got := FormatKey(key); got != want {
			t.Errorf("FormatKey(%q) = %s, want %s", key, got, want)
		}
	}
}
