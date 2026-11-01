package codex

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

func TestApplyDiffAppliesOnlyAnExactDiff(t *testing.T) {
	cases := []struct {
		name, old, diff, want string
		ok                    bool
	}{
		{"one line", "hello\n", "@@ -1 +1 @@\n-hello\n+world\n", "world\n", true},
		{"two hunks with context", "a\nb\nc\nd\ne\nf\ng\n", "@@ -1,2 +1,2 @@\n-a\n+A\n b\n@@ -6,2 +6,3 @@\n f\n-g\n+G\n+h\n", "A\nb\nc\nd\ne\nf\nG\nh\n", true},
		{"insert into an empty file", "", "@@ -0,0 +1 @@\n+x\n", "x\n", true},
		{"insert after a line", "a\nb\n", "@@ -1,0 +2 @@\n+x\n", "a\nx\nb\n", true},
		{"delete every line", "a\nb\n", "@@ -1,2 +0,0 @@\n-a\n-b\n", "", true},
		{"old without a final newline", "a\nb", "@@ -2 +2 @@\n-b\n\\ No newline at end of file\n+b\n", "a\nb\n", true},
		{"new without a final newline", "a\n", "@@ -1 +1 @@\n-a\n+a\n\\ No newline at end of file\n", "a", true},
		{"CRLF lines", "a\r\nb\r\n", "@@ -2 +2 @@\n-b\r\n+c\r\n", "a\r\nc\r\n", true},
		{"removed line differs", "hello\n", "@@ -1 +1 @@\n-hullo\n+world\n", "", false},
		{"context differs", "a\nb\n", "@@ -1,2 +1,2 @@\n x\n-b\n+c\n", "", false},
		{"count too high", "a\n", "@@ -1,2 +1 @@\n-a\n+b\n", "", false},
		{"count too low", "a\nb\n", "@@ -1 +1 @@\n-a\n-b\n+c\n", "", false},
		{"past the end", "a\n", "@@ -3 +3 @@\n-c\n+d\n", "", false},
		{"overlapping hunks", "a\nb\nc\n", "@@ -2 +2 @@\n-b\n+B\n@@ -1 +1 @@\n-a\n+A\n", "", false},
		{"new start that does not land", "a\nb\n", "@@ -2 +5 @@\n-b\n+c\n", "", false},
		{"file headers", "a\n", "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n", "", false},
		{"text after the header", "a\n", "@@ -1 +1 @@ func\n-a\n+b\n", "", false},
		{"an empty line in a hunk", "a\n\nb\n", "@@ -1,3 +1,3 @@\n a\n\n-b\n+c\n", "", false},
		{"marker with no line", "a\n", "@@ -1 +1 @@\n\\ No newline at end of file\n-a\n+b\n", "", false},
		{"no final newline in the diff", "a\n", "@@ -1 +1 @@\n-a\n+b", "", false},
		{"empty diff", "a\n", "", "", false},
		{"empty hunk", "a\n", "@@ -1,0 +1,0 @@\n", "", false},
		{"line where a hunk header belongs", "a\n", "@@ -1 +1 @@\n-a\n+b\n+c\n", "", false},
	}
	for _, c := range cases {
		got, ok := applyDiff(c.old, c.diff)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s: got %q %v, want %q %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestWholeFileReadIsOnlyACompleteCat(t *testing.T) {
	read := func(mod func(*item)) item {
		out, zero := "seed\n", int32(0)
		it := item{Type: "CommandExecution", Command: []string{"/bin/bash", "-lc", "cat b.txt"}, Cwd: "file:///ws/basic",
			ParsedCmd: []parsedCmd{{Type: "read", Cmd: "cat b.txt", Path: "b.txt"}}, AggregatedOutput: &out, Status: "completed", ExitCode: &zero}
		if mod != nil {
			mod(&it)
		}
		return it
	}
	if p, text, ok := wholeFileRead(read(nil)); !ok || p != "/ws/basic/b.txt" || text != "seed\n" {
		t.Errorf("the cat of b.txt reads %q %q %v", p, text, ok)
	}
	if p, _, ok := wholeFileRead(read(func(it *item) {
		it.Command[2], it.ParsedCmd[0].Cmd, it.ParsedCmd[0].Path, it.Cwd = "cat /ws/x/b.txt", "cat /ws/x/b.txt", "/ws/x/b.txt", ""
	})); !ok || p != "/ws/x/b.txt" {
		t.Errorf("an absolute cat reads %q %v", p, ok)
	}
	one := int32(1)
	refused := map[string]func(*item){
		"a cut output":           func(it *item) { s := "seed\n…12 tokens truncated…\n"; it.AggregatedOutput = &s },
		"output cut for storage": func(it *item) { s := "a\n... command output truncated for persistence ...\n"; it.AggregatedOutput = &s },
		"a lossy output":         func(it *item) { s := "se�d\n"; it.AggregatedOutput = &s },
		"no output":              func(it *item) { it.AggregatedOutput = nil },
		"exit code 1":            func(it *item) { it.ExitCode = &one },
		"failed":                 func(it *item) { it.Status = "failed" },
		"a sed":                  func(it *item) { it.Command[2], it.ParsedCmd[0].Cmd = "sed -n 1,2p b.txt", "sed -n 1,2p b.txt" },
		"two files":              func(it *item) { it.Command[2], it.ParsedCmd[0].Cmd = "cat b.txt c.txt", "cat b.txt c.txt" },
		"a quoted word":          func(it *item) { it.Command[2], it.ParsedCmd[0].Cmd = "cat 'b.txt'", "cat 'b.txt'" },
		"an option":              func(it *item) { it.Command[2], it.ParsedCmd[0].Cmd, it.ParsedCmd[0].Path = "cat -n", "cat -n", "-n" },
		"a parent directory": func(it *item) {
			it.Command[2], it.ParsedCmd[0].Cmd, it.ParsedCmd[0].Path = "cat ../b.txt", "cat ../b.txt", "../b.txt"
		},
		"Codex parsed otherwise":  func(it *item) { it.ParsedCmd[0].Type = "unknown" },
		"another path parsed":     func(it *item) { it.ParsedCmd[0].Path = "c.txt" },
		"two parsed commands":     func(it *item) { it.ParsedCmd = append(it.ParsedCmd, it.ParsedCmd[0]) },
		"no working directory":    func(it *item) { it.Cwd = "" },
		"an escaped directory":    func(it *item) { it.Cwd = "file:///ws/a%20b" },
		"another command wrapper": func(it *item) { it.Command = []string{"/bin/sh", "-c", "cat b.txt"} },
	}
	for name, mod := range refused {
		if _, _, ok := wholeFileRead(read(mod)); ok {
			t.Errorf("%s is read as the whole file", name)
		}
	}
}

// itemSE is an item with its start and completion times.
func itemSE(ts string, started, completed int64, it string) string {
	return `{"timestamp":"` + ts + `","type":"event_msg","payload":{"type":"item_completed","thread_id":"` + thread + `","turn_id":"t1","started_at_ms":` + itoa(started) + `,"completed_at_ms":` + itoa(completed) + `,"item":` + it + `}}`
}

func catItem(file, out string) string {
	o, _ := json.Marshal(out)
	return `{"type":"CommandExecution","id":"r","command":["/bin/bash","-lc","cat ` + file + `"],"cwd":"file:///ws/basic","parsed_cmd":[{"type":"read","cmd":"cat ` + file + `","path":"` + file + `"}],"aggregated_output":` + string(o) + `,"status":"completed","exit_code":0}`
}

func updateItem(path, diff string) string {
	d, _ := json.Marshal(diff)
	return `{"type":"FileChange","id":"u","changes":{"` + path + `":{"type":"update","unified_diff":` + string(d) + `,"move_path":null}},"status":"completed"}`
}

// updateHashes parses a rollout of one cell per item, at one second apart,
// and returns the hash each update's write claims ("" for none) and the
// report's degradations.
func updateHashes(t *testing.T, items []string, extra ...string) ([]string, []string) {
	t.Helper()
	lines := []string{meta(thread)}
	for i, it := range items {
		sec := 20 + 2*i
		ts := func(ms int) string { return "2026-10-31T23:40:" + itoa(int64(sec)) + "." + itoa(int64(ms)) + "Z" }
		ms := func(d int) int64 { return 1793490000000 + int64(sec)*1000 + int64(d) }
		id := "c" + itoa(int64(i))
		lines = append(lines, call(ts(100), id), itemSE(ts(200), ms(150), ms(200), it), output(ts(300), id))
	}
	lines = append(lines, extra...)
	tr, rep, err := Adapter{}.Parse(write(t, filepath.Join(t.TempDir(), "r.rollout.jsonl"), lines...))
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	var hashes []string
	for _, c := range tr {
		if c.Tool == toolUpdate && c.ActionType == models.FileWrite {
			h := ""
			if c.OutputHash != nil {
				h = *c.OutputHash
			}
			hashes = append(hashes, h)
		}
	}
	return hashes, rep.Degradations
}

func TestAnUpdateClaimsTheContentItsDiffGivesTheRecordedContent(t *testing.T) {
	world, again, there := content.SHA256Bytes([]byte("world\n")), content.SHA256Bytes([]byte("again\n")), content.SHA256Bytes([]byte("there\n"))
	add := `{"type":"FileChange","id":"a","changes":{"/ws/basic/a.txt":{"type":"add","content":"hello\n"}},"status":"completed"}`
	cases := []struct {
		name  string
		items []string
		extra []string
		want  []string
	}{
		{"after an add", []string{add, updateItem("/ws/basic/a.txt", "@@ -1 +1 @@\n-hello\n+world\n")}, nil, []string{world}},
		{"after a whole-file cat", []string{catItem("b.txt", "seed\n"), updateItem("/ws/basic/b.txt", "@@ -1 +1 @@\n-seed\n+again\n")}, nil, []string{again}},
		{"a chain of updates", []string{add, updateItem("/ws/basic/a.txt", "@@ -1 +1 @@\n-hello\n+world\n"), updateItem("/ws/basic/a.txt", "@@ -1 +1 @@\n-world\n+there\n")}, nil, []string{world, there}},
		{"a cat of another file", []string{catItem("c.txt", "seed\n"), updateItem("/ws/basic/b.txt", "@@ -1 +1 @@\n-seed\n+again\n")}, nil, []string{""}},
		{"no prior content", []string{updateItem("/ws/basic/b.txt", "@@ -1 +1 @@\n-seed\n+again\n")}, nil, []string{""}},
		{"a diff that does not apply", []string{catItem("b.txt", "other\n"), updateItem("/ws/basic/b.txt", "@@ -1 +1 @@\n-seed\n+again\n")}, nil, []string{""}},
		{"a failed update ends the chain", []string{add, updateItem("/ws/basic/a.txt", "@@ -1 +1 @@\n-nope\n+world\n"), updateItem("/ws/basic/a.txt", "@@ -1 +1 @@\n-world\n+there\n")}, nil, []string{"", ""}},
		{"a command between", []string{catItem("b.txt", "seed\n"),
			`{"type":"CommandExecution","id":"x","command":["/bin/bash","-lc","echo x > b.txt"],"status":"completed","exit_code":0}`,
			updateItem("/ws/basic/b.txt", "@@ -1 +1 @@\n-seed\n+again\n")}, nil, []string{""}},
		{"a command after, in a later cell", []string{catItem("b.txt", "seed\n"), updateItem("/ws/basic/b.txt", "@@ -1 +1 @@\n-seed\n+again\n"),
			`{"type":"CommandExecution","id":"x","command":["/bin/bash","-lc","echo hi"],"status":"completed","exit_code":0}`}, nil, []string{again}},
		{"a command joined to no cell", []string{catItem("b.txt", "seed\n"), updateItem("/ws/basic/b.txt", "@@ -1 +1 @@\n-seed\n+again\n")},
			[]string{itemSE("2026-10-31T23:40:50.000Z", 1793490050000, 1793490050000, `{"type":"CommandExecution","id":"x","command":["/bin/bash","-lc","sleep 30; echo x > b.txt"],"status":"completed","exit_code":0}`)},
			[]string{""}},
		{"a cut output", []string{catItem("b.txt", "seed\n[... 3 chars truncated ...]\n"), updateItem("/ws/basic/b.txt", "@@ -1 +1 @@\n-seed\n+again\n")}, nil, []string{""}},
		{"a delete between", []string{add, `{"type":"FileChange","id":"d","changes":{"/ws/basic/a.txt":{"type":"delete"}},"status":"completed"}`,
			updateItem("/ws/basic/a.txt", "@@ -1 +1 @@\n-hello\n+world\n")}, nil, []string{""}},
		{"a wait call in the rollout", []string{add, updateItem("/ws/basic/a.txt", "@@ -1 +1 @@\n-hello\n+world\n")},
			[]string{`{"timestamp":"2026-10-31T23:40:59.000Z","type":"response_item","payload":{"type":"function_call","name":"wait","call_id":"w"}}`}, []string{""}},
		{"a subagent started", []string{add, updateItem("/ws/basic/a.txt", "@@ -1 +1 @@\n-hello\n+world\n")},
			[]string{itemSE("2026-10-31T23:40:59.000Z", 1793490059000, 1793490059000, `{"type":"SubAgentActivity","id":"s","kind":"started","agent_thread_id":"other"}`)}, []string{""}},
	}
	for _, c := range cases {
		got, deg := updateHashes(t, c.items, c.extra...)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: update hashes %q, want %q", c.name, got, c.want)
		}
		claimed, unclaimed := 0, 0
		for _, h := range c.want {
			if h != "" {
				claimed++
			} else {
				unclaimed++
			}
		}
		joined := strings.Join(deg, "\n")
		if (claimed > 0) != strings.Contains(joined, itoa(int64(claimed))+" update(s) by apply_patch claim the content") ||
			(unclaimed > 0) != strings.Contains(joined, itoa(int64(unclaimed))+" update(s) by apply_patch are recorded as a diff without") {
			t.Errorf("%s: degradations %q", c.name, deg)
		}
	}
}

// The update must start after its content's source completed: an update
// whose start is not recorded, or not after the read, claims nothing.
func TestAnUpdateMustStartAfterItsSourceCompleted(t *testing.T) {
	cat := catItem("b.txt", "seed\n")
	upd := updateItem("/ws/basic/b.txt", "@@ -1 +1 @@\n-seed\n+again\n")
	for name, lines := range map[string][]string{
		"same millisecond": {meta(thread), call("2026-10-31T23:40:20.000Z", "c1"),
			itemSE("2026-10-31T23:40:20.100Z", 1793490020100, 1793490020100, cat),
			itemSE("2026-10-31T23:40:20.100Z", 1793490020100, 1793490020100, upd), output("2026-10-31T23:40:20.300Z", "c1")},
		"no start": {meta(thread), call("2026-10-31T23:40:20.000Z", "c1"),
			itemSE("2026-10-31T23:40:20.100Z", 1793490020100, 1793490020100, cat),
			itemAt("2026-10-31T23:40:20.200Z", 1793490020200, upd), output("2026-10-31T23:40:20.300Z", "c1")},
	} {
		tr, _, err := Adapter{}.Parse(write(t, filepath.Join(t.TempDir(), "r.rollout.jsonl"), lines...))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range tr {
			if c.Tool == toolUpdate && c.OutputHash != nil {
				t.Errorf("%s: the update claims a hash", name)
			}
		}
	}
}
