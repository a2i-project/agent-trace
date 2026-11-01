package codex

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const thread = "01a19455-d74e-72a2-99d3-367c07be5a85"

func write(t *testing.T, path string, lines ...string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func meta(id string) string {
	return `{"timestamp":"2026-10-31T23:40:16.726Z","ordinal":0,"type":"session_meta","payload":{"id":"` + id + `","session_id":"` + id + `","cli_version":"0.166.0","cwd":"/ws/basic"}}`
}

func call(ts, id string) string {
	return `{"timestamp":"` + ts + `","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"` + id + `","status":"completed","internal_chat_message_metadata_passthrough":{"turn_id":"t1"}}}`
}

func output(ts, id string) string {
	return `{"timestamp":"` + ts + `","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"` + id + `"}}`
}

func itemAt(ts string, ms int64, it string) string {
	return `{"timestamp":"` + ts + `","type":"event_msg","payload":{"type":"item_completed","thread_id":"` + thread + `","turn_id":"t1","completed_at_ms":` + itoa(ms) + `,"item":` + it + `}}`
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}

// The basic task's shape: a command, an add, an update, a second command.
func basicRollout(t *testing.T, dir string) string {
	return write(t, filepath.Join(dir, "basic.rollout.jsonl"),
		meta(thread),
		call("2026-10-31T23:40:20.463Z", "c1"),
		itemAt("2026-10-31T23:40:20.521Z", 1793490020521, `{"type":"CommandExecution","id":"e1","command":["/bin/bash","-lc","cat b.txt"],"status":"completed","exit_code":0}`),
		output("2026-10-31T23:40:20.524Z", "c1"),
		call("2026-10-31T23:40:21.678Z", "c2"),
		itemAt("2026-10-31T23:40:21.686Z", 1793490021686, `{"type":"FileChange","id":"e2","changes":{"/ws/basic/a.txt":{"type":"add","content":"hello\n"}},"status":"completed"}`),
		output("2026-10-31T23:40:21.689Z", "c2"),
		call("2026-10-31T23:40:22.947Z", "c3"),
		itemAt("2026-10-31T23:40:22.954Z", 1793490022954, `{"type":"FileChange","id":"e3","changes":{"/ws/basic/a.txt":{"type":"update","unified_diff":"@@","move_path":null}},"status":"completed"}`),
		output("2026-10-31T23:40:22.956Z", "c3"),
		itemAt("2026-10-31T23:40:25.775Z", 1793490025775, `{"type":"AgentMessage","id":"m"}`),
	)
}

func TestDetectReadsTheSessionMeta(t *testing.T) {
	dir := t.TempDir()
	p := basicRollout(t, dir)
	if !(Adapter{}).Detect(p) {
		t.Error("a rollout is not detected")
	}
	other := write(t, filepath.Join(dir, "x.jsonl"), `{"type":"user","sessionId":"s","version":"2.1.306"}`)
	if (Adapter{}).Detect(other) {
		t.Error("a Claude Code transcript is detected as a rollout")
	}
	if (Adapter{}).Detect(strings.TrimSuffix(p, ".jsonl") + ".txt") {
		t.Error("a file that is not .jsonl is detected")
	}
}

func TestParseClaimsEachEffectWithItsCellsInterval(t *testing.T) {
	tr, rep, err := Adapter{}.Parse(basicRollout(t, t.TempDir()))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	want := []struct {
		t      models.ActionType
		target string
		hash   bool
	}{
		{models.ProcessExec, "cat b.txt", false},
		{models.FileOpen, "/ws/basic/a.txt", false},
		{models.FileWrite, "/ws/basic/a.txt", true},
		{models.FileOpen, "/ws/basic/a.txt", false},
		{models.FileWrite, "/ws/basic/a.txt", false},
	}
	if len(tr) != len(want) || rep.AgentVersion != "0.166.0" || rep.ToolCalls != 3 || rep.Entries != 5 {
		t.Fatalf("%d claims, version %q, %d calls, %d entries: %+v", len(tr), rep.AgentVersion, rep.ToolCalls, rep.Entries, tr)
	}
	for i, w := range want {
		c := tr[i]
		if c.ActionType != w.t || c.Target != w.target || (c.OutputHash != nil) != w.hash || c.End == nil || c.BlockID != "" {
			t.Errorf("claim %d = %+v, want %v %s hash %v with an end and no block", i, c, w.t, w.target, w.hash)
		}
	}
	if h := content.SHA256Bytes([]byte("hello\n")); *tr[2].OutputHash != h {
		t.Errorf("the add's hash is %s, want the content's", *tr[2].OutputHash)
	}
	if tr[0].Timestamp.Format("15:04:05.000") != "23:40:20.463" || tr[0].End.Format("15:04:05.000") != "23:40:20.524" {
		t.Errorf("the command's interval is %v to %v, want its cell's", tr[0].Timestamp, tr[0].End)
	}
}

// Two effects of one cell form a block; an effect no single cell holds is a
// point with a degradation; a failed change, a command with no exit code,
// an unknown item and an unknown direct tool are counted, the last two
// listed as unknown; a line that does not parse is a parse error.
func TestParseCountsWhatItDoesNotClaim(t *testing.T) {
	p := write(t, filepath.Join(t.TempDir(), "r.rollout.jsonl"),
		meta(thread),
		call("2026-10-31T23:40:20.000Z", "c1"),
		itemAt("2026-10-31T23:40:20.100Z", 1793490020100, `{"type":"CommandExecution","id":"e1","command":["/bin/bash","-lc","echo a"],"status":"completed","exit_code":0}`),
		itemAt("2026-10-31T23:40:20.200Z", 1793490020200, `{"type":"CommandExecution","id":"e2","command":["/bin/bash","-lc","echo b"],"status":"failed","exit_code":1}`),
		itemAt("2026-10-31T23:40:20.300Z", 1793490020300, `{"type":"FileChange","id":"e3","changes":{"/ws/x":{"type":"add","content":""}},"status":"failed"}`),
		itemAt("2026-10-31T23:40:20.400Z", 1793490020400, `{"type":"CommandExecution","id":"e4","command":["/bin/bash","-lc","sleep 9"],"status":"declined","exit_code":null}`),
		itemAt("2026-10-31T23:40:20.500Z", 1793490020500, `{"type":"McpToolCall","id":"e5"}`),
		output("2026-10-31T23:40:20.600Z", "c1"),
		itemAt("2026-10-31T23:40:30.000Z", 1793490030000, `{"type":"CommandExecution","id":"e6","command":["/bin/bash","-lc","late"],"status":"completed","exit_code":0}`),
		`{"timestamp":"2026-10-31T23:40:31.000Z","type":"response_item","payload":{"type":"function_call","name":"spawn_agent","call_id":"f1"}}`,
		`{"timestamp":"2026-10-31T23:40:32.000Z","type":"response_item","payload":{"type":"function_call","name":"rm_rf","call_id":"f2"}}`,
		`not json`,
	)
	tr, rep, err := Adapter{}.Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 3 || tr[0].BlockID == "" || tr[0].BlockID != tr[1].BlockID || tr[2].Target != "late" || tr[2].End != nil {
		t.Errorf("claims %+v: want echo a and echo b in one block, then late as a point", tr)
	}
	if rep.UnmappedByTool["apply_patch (status failed)"] != 1 || rep.UnmappedByTool["exec_command (status declined)"] != 1 ||
		rep.UnmappedByTool["item McpToolCall"] != 1 || rep.UnmappedByTool["spawn_agent"] != 1 || rep.UnmappedByTool["rm_rf"] != 1 {
		t.Errorf("unmapped %v", rep.UnmappedByTool)
	}
	if strings.Join(rep.UnknownTools, ",") != "item McpToolCall,rm_rf" {
		t.Errorf("unknown %v", rep.UnknownTools)
	}
	if len(rep.ParseErrors) != 1 || !strings.Contains(strings.Join(rep.Degradations, ";"), "joined to no single cell") {
		t.Errorf("parse errors %v, degradations %v", rep.ParseErrors, rep.Degradations)
	}
}

// A command that outlived the cell that started it, an exec_command that
// yielded a session (I-94), is claimed from that cell's start to its own
// completion, whether it completed between cells or in a later one; a file
// change of the same shape and a command whose start no cell holds are
// joined by their completion as before.
func TestParseClaimsAnOutlivingCommandFromTheCellThatStartedIt(t *testing.T) {
	cmd := func(id, line string) string {
		return `{"type":"CommandExecution","id":"` + id + `","command":["/bin/bash","-lc","` + line + `"],"status":"completed","exit_code":0}`
	}
	p := write(t, filepath.Join(t.TempDir(), "r.rollout.jsonl"),
		meta(thread),
		call("2026-10-31T23:40:20.000Z", "c1"),
		output("2026-10-31T23:40:20.600Z", "c1"),
		call("2026-10-31T23:40:21.000Z", "c2"),
		itemSE("2026-10-31T23:40:21.100Z", 1793490021100, 1793490021100, cmd("e1", "echo b")),
		output("2026-10-31T23:40:21.200Z", "c2"),
		itemSE("2026-10-31T23:40:22.000Z", 1793490020100, 1793490022000, cmd("e2", "sleep 2; echo a")),
		itemSE("2026-10-31T23:40:22.100Z", 1793490020200, 1793490022100, `{"type":"FileChange","id":"e3","changes":{"/ws/x":{"type":"add","content":""}},"status":"completed"}`),
		call("2026-10-31T23:40:23.000Z", "c3"),
		itemSE("2026-10-31T23:40:23.050Z", 1793490021050, 1793490023050, cmd("e4", "sleep 2; echo c")),
		itemSE("2026-10-31T23:40:23.060Z", 1793490019000, 1793490023060, cmd("e5", "early")),
		output("2026-10-31T23:40:23.100Z", "c3"),
	)
	tr, rep, err := Adapter{}.Parse(p)
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	at := func(c models.TrajectoryEntry) string {
		end := "none"
		if c.End != nil {
			end = c.End.Format("05.000")
		}
		return c.Target + " " + c.Timestamp.Format("05.000") + " " + end + " " + c.BlockID
	}
	var got []string
	for _, c := range tr {
		got = append(got, at(c))
	}
	block := thread + "/c2"
	want := []string{
		"sleep 2; echo a 20.000 22.000 ",
		"echo b 21.000 21.200 " + block,
		"sleep 2; echo c 21.000 23.050 " + block,
		"/ws/x 22.100 none ",
		"/ws/x 22.100 none ",
		"early 23.000 23.100 ",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("claims:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	deg := strings.Join(rep.Degradations, ";")
	if !strings.Contains(deg, "2 command(s) outlived the cell that started them") || !strings.Contains(deg, "1 effect(s) joined to no single cell") {
		t.Errorf("degradations %v", rep.Degradations)
	}
}

func TestParseFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]string{
		"no session_meta": {call("2026-10-31T23:40:20.000Z", "c1")},
		"no version":      {`{"timestamp":"2026-10-31T23:40:16.726Z","type":"session_meta","payload":{"id":"x"}}`},
		"empty":           {""},
	}
	for name, lines := range cases {
		if _, _, err := (Adapter{}).Parse(write(t, filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".jsonl"), lines...)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// A command in another form and an item of another thread are parse
	// errors, never claims.
	p := write(t, filepath.Join(dir, "odd.jsonl"),
		meta(thread),
		itemAt("2026-10-31T23:40:20.100Z", 1793490020100, `{"type":"CommandExecution","id":"e1","command":["/bin/zsh","-c","x"],"status":"completed","exit_code":0}`),
		strings.Replace(itemAt("2026-10-31T23:40:20.200Z", 1793490020200, `{"type":"CommandExecution","id":"e2","command":["/bin/bash","-lc","y"],"status":"completed","exit_code":0}`), thread, "other", 1),
	)
	tr, rep, err := Adapter{}.Parse(p)
	if err != nil || len(tr) != 0 || len(rep.ParseErrors) != 2 {
		t.Errorf("claims %v, parse errors %v, err %v", tr, rep.ParseErrors, err)
	}
}

// A subagent's rollout, copied by the capture beside the main one, is read
// from its history start ordinal on, its claims carry its thread id, and a
// rollout of another session is not read.
func TestParseFollowsSubagentRollouts(t *testing.T) {
	dir := t.TempDir()
	main := write(t, filepath.Join(dir, "task.rollout.jsonl"),
		meta(thread),
		itemAt("2026-10-31T23:40:20.000Z", 1793490020000, `{"type":"SubAgentActivity","id":"f1","kind":"started","agent_thread_id":"sub-1"}`),
		itemAt("2026-10-31T23:40:20.000Z", 1793490020000, `{"type":"SubAgentActivity","id":"f2","kind":"started","agent_thread_id":"sub-2"}`),
	)
	subMeta := `{"timestamp":"2026-10-31T23:40:20.100Z","ordinal":0,"type":"session_meta","payload":{"id":"sub-1","session_id":"` + thread + `","cli_version":"0.166.0","subagent_history_start_ordinal":3}}`
	subItem := func(ord, th, cmd string) string {
		return `{"timestamp":"2026-10-31T23:40:21.000Z","ordinal":` + ord + `,"type":"event_msg","payload":{"type":"item_completed","thread_id":"` + th + `","turn_id":"t2","completed_at_ms":1793490021000,"item":{"type":"CommandExecution","id":"x","command":["/bin/bash","-lc","` + cmd + `"],"status":"completed","exit_code":0}}}`
	}
	write(t, filepath.Join(dir, "task.rollout", "subagents", "a.jsonl"),
		subMeta, strings.Replace(meta(thread), `"ordinal":0`, `"ordinal":1`, 1),
		subItem("2", thread, "parent history"),
		subItem("3", "sub-1", "echo sub"),
	)
	write(t, filepath.Join(dir, "task.rollout", "subagents", "b.jsonl"),
		strings.Replace(subMeta, thread, "another-session", 1))
	tr, rep, err := Adapter{}.Parse(main)
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("%v %v", err, rep.ParseErrors)
	}
	if len(tr) != 1 || tr[0].Target != "echo sub" || tr[0].ThreadID != "sub-1" {
		t.Errorf("claims %+v, want the subagent's own command with its thread", tr)
	}
	d := strings.Join(rep.Degradations, ";")
	if !strings.Contains(d, "is not a subagent of session") || !strings.Contains(d, "1 subagent(s) started with no rollout") {
		t.Errorf("degradations %v", rep.Degradations)
	}
}

func TestDeclarations(t *testing.T) {
	a := Adapter{}
	if p := a.Process(); !p.ShellPerCommand || !p.SubagentsInProcess || p.ExitsClaimed || p.IntervalKind != agent.IntervalDecision {
		t.Errorf("process model %+v", p)
	}
	add := models.TrajectoryEntry{Tool: toolAdd}
	upd := models.TrajectoryEntry{Tool: toolUpdate}
	h := "sha256:x"
	updWithContent := models.TrajectoryEntry{Tool: toolUpdate, OutputHash: &h}
	if !a.Expresses(add, verification.DiffOutputHash) || a.Expresses(upd, verification.DiffOutputHash) || !a.Expresses(updWithContent, verification.DiffOutputHash) ||
		a.Expresses(add, verification.DiffExitCode) || a.Expresses(add, verification.DiffRequestHash) {
		t.Error("Expresses: an add states its content, an update only when its content was known (I-87), nothing states an exit code or a body")
	}
	for p, want := range map[string]bool{
		"/home/u/.codex/sessions/x.jsonl": true, "/root/.codex": true, "/home/u/.codexx/a": false, "/ws/.codex/config.toml": false,
	} {
		if a.IsHarnessOwned(p) != want {
			t.Errorf("IsHarnessOwned(%s) != %v", p, want)
		}
	}
	if len(a.HarnessHosts()) != 0 || len(a.HarnessCommands()) != 1 {
		t.Error("the capture showed no occasional host and one occasional command")
	}
	bk := a.HarnessBookkeeping("0.166.0", "/home/u")
	for e, want := range map[models.GroundTruthEvent]bool{
		{ActionType: models.FileDelete, Target: "/home/u/.codex/state_5.sqlite-wal"}:  true,
		{ActionType: models.FileWrite, Target: "/home/u/.codex/logs_2.sqlite"}:        true,
		{ActionType: models.FileOpen, Target: "/home/u/.codex/logs_2.sqlite"}:         false,
		{ActionType: models.FileWrite, Target: "/home/v/.codex/logs_2.sqlite"}:        false,
		{ActionType: models.FileWrite, Target: "/home/u/.codex/auth.json"}:            false,
		{ActionType: models.FileWrite, Target: "/home/u/.codex/other_1.sqlite-wal"}:   false,
		{ActionType: models.FileWrite, Target: "/home/u/.codex/state_5.sqlite-wal.x"}: false,
	} {
		if bk(e) != want {
			t.Errorf("bookkeeping %v %s != %v", e.ActionType, e.Target, want)
		}
	}
	if a.HarnessBookkeeping("0.167.0", "") != nil {
		t.Error("an unmeasured version declares bookkeeping")
	}
	tr := a.Trace("/ws/basic", "/home/u")
	for p, want := range map[string][2]bool{ // covers, main
		"/home/u/.codex/sessions/2026/11/01/rollout-2026-11-01T00-40-16-" + thread + ".jsonl": {true, true},
		"/home/u/.codex/state_5.sqlite":              {true, false},
		"/home/u/.codex/thread_history_1.sqlite-wal": {true, false},
		"/home/u/.codex/logs_2.sqlite":               {false, false},
		"/home/v/.codex/state_5.sqlite":              {false, false},
		"/home/u/.codex/sessions/2026/11/01/x.jsonl": {false, false},
	} {
		if tr.Covers(p) != want[0] || tr.Main(p) != want[1] {
			t.Errorf("trace %s: covers %v main %v, want %v", p, tr.Covers(p), tr.Main(p), want)
		}
	}
	if a.Trace("", "relative") != nil {
		t.Error("a home that is not a home declares a trace")
	}
	for _, f := range a.SensitiveFiles() {
		if !strings.HasPrefix(f, "~/") && !strings.HasPrefix(f, "{workspace}/") {
			t.Errorf("sensitive file %s", f)
		}
	}
}

func TestCanonicalReplacesThePerRunIDs(t *testing.T) {
	for in, want := range map[string]string{
		"/home/u/.codex/sessions/2026/11/01/rollout-2026-11-01T00-40-16-" + thread + ".jsonl": "/home/u/.codex/sessions/{date}/rollout-{time}-{id}.jsonl",
		"/home/u/.codex/shell_snapshots/" + thread + ".tmp-1793490016080416876":               "/home/u/.codex/shell_snapshots/{id}.tmp-{n}",
		"/home/u/.codex/shell_snapshots/" + thread + ".1793490016080416876.sh":                "/home/u/.codex/shell_snapshots/{id}.{n}.sh",
		"/home/u/.codex/tmp/arg0-linux/codex-arg0zmUStF/apply_patch":                          "/home/u/.codex/tmp/arg0-linux/codex-arg0{id}/apply_patch",
		"/home/u/.codex/thread-writer-locks/" + thread + ".lock":                              "/home/u/.codex/thread-writer-locks/{id}.lock",
		"/home/u/.codex/cache/codex_apps_tools/.tmpMuwQ1i":                                    "/home/u/.codex/cache/codex_apps_tools/.tmp{id}",
		`/bin/bash -c set -e; . "/home/u/.codex/shell_snapshots/` + thread + `.tmp-17"`:       `/bin/bash -c set -e; . "/home/u/.codex/shell_snapshots/{id}.tmp-{n}"`,
		"/ws/basic/" + thread + ".tmp-1":                                                      "/ws/basic/" + thread + ".tmp-1",
	} {
		if got := (Adapter{}).Canonical(models.GroundTruthEvent{ActionType: models.FileOpen, Target: in}).Target; got != want {
			t.Errorf("Canonical(%s) = %s, want %s", in, got, want)
		}
	}
}

func ev(ms int, pid uint32, t models.ActionType, target string) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: time.Unix(1000, 0).Add(time.Duration(ms) * time.Microsecond), PID: pid, ActionType: t, Target: target}
}

func TestNormalizeStreamFoldsTheMeasuredShapes(t *testing.T) {
	h := content.SHA256Bytes([]byte("hello\n"))
	empty := emptyHash
	open0 := ev(1, 1, models.FileOpen, "/ws/a.txt")
	open0.InputHash = &empty
	closeA := ev(2, 1, models.FileClose, "/ws/a.txt")
	closeA.OutputHash = &h
	g := models.GroundTruth{
		// A PATH search of a helper by a command process.
		ev(0, 5, models.ProcessFork, "5"),
		ev(0, 5, models.ProcessExec, "/home/u/.codex/tmp/arg0-linux/codex-arg0abcdef/git remote -v"),
		ev(0, 5, models.ProcessExec, "/usr/local/bin/git remote -v"),
		ev(1, 5, models.ProcessExec, "/usr/bin/git remote -v"),
		// An add by the agent's process.
		ev(1, 1, models.FileWrite, "/ws/a.txt"),
		open0,
		ev(2, 1, models.FileWrite, "/ws/a.txt"),
		closeA,
		// An update: three opens with another thread's network event between.
		ev(10, 1, models.FileOpen, "/ws/b.txt"),
		ev(11, 1, models.NetBind, "0.0.0.0:0"),
		ev(12, 1, models.FileOpen, "/ws/b.txt"),
		ev(13, 1, models.FileOpen, "/ws/b.txt"),
		ev(14, 1, models.FileWrite, "/ws/b.txt"),
		ev(15, 1, models.FileClose, "/ws/b.txt"),
	}
	got := Adapter{}.NormalizeStream(g)
	var lines []string
	for _, e := range got {
		s := string(e.ActionType) + " " + e.Target
		if e.OutputHash != nil {
			s += " #"
		}
		lines = append(lines, s)
	}
	want := []string{
		"process_fork 5", "process_exec /usr/bin/git remote -v",
		"file_open /ws/a.txt", "file_write /ws/a.txt #",
		"file_open /ws/b.txt", "net_bind 0.0.0.0:0", "file_write /ws/b.txt",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// What the folds leave alone: a command's own file events, the harness's
// files, a write with another file's event between, and two execs of one
// program from the same directory or with other arguments.
func TestNormalizeStreamIsNarrow(t *testing.T) {
	g := models.GroundTruth{
		ev(0, 7, models.ProcessExec, "/usr/bin/tee x"),
		ev(1, 7, models.FileOpen, "/ws/x"),
		ev(2, 7, models.FileWrite, "/ws/x"),
		ev(3, 7, models.FileClose, "/ws/x"),
		ev(4, 1, models.FileOpen, "/home/u/.codex/sessions/r.jsonl"),
		ev(5, 1, models.FileWrite, "/home/u/.codex/sessions/r.jsonl"),
		ev(6, 1, models.FileClose, "/home/u/.codex/sessions/r.jsonl"),
		ev(7, 1, models.FileOpen, "/ws/y"),
		ev(8, 1, models.FileOpen, "/ws/z"),
		ev(9, 1, models.FileWrite, "/ws/y"),
		ev(10, 1, models.FileClose, "/ws/y"),
		ev(11, 8, models.ProcessExec, "/a/ls -l"),
		ev(12, 8, models.ProcessExec, "/b/ls -a"),
		ev(13, 9, models.ProcessExec, "/a/ls -l"),
		ev(14, 9, models.ProcessExec, "/a/ls -l"),
	}
	if got := (Adapter{}).NormalizeStream(append(models.GroundTruth{}, g...)); len(got) != len(g) {
		t.Errorf("%d events of %d kept: %+v", len(got), len(g), got)
	}
}

func TestHarnessProcessIsTheNativeBinaryTheLauncherStarted(t *testing.T) {
	native := "/home/u/.npm-global/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex exec --json hi"
	g := models.GroundTruthFile{RootPID: 10, Events: models.GroundTruth{
		ev(0, 10, models.FileOpen, "/home/u/.npm-global/lib/node_modules/@openai/codex/bin/codex.js"),
		{Timestamp: time.Unix(1000, 0), PID: 11, PPID: 10, ActionType: models.ProcessFork, Target: "11"},
		{Timestamp: time.Unix(1000, 0), PID: 11, PPID: 10, ActionType: models.ProcessExec, Target: native},
	}}
	if pid := (Adapter{}).HarnessProcess(g); pid != 11 {
		t.Errorf("harness %d, want 11", pid)
	}
	if r := agent.Rooted(Adapter{}, g); r.RootPID != 11 {
		t.Errorf("rooted at %d", r.RootPID)
	}
	noScript := g
	noScript.Events = g.Events[1:]
	other := g
	other.Events = append(models.GroundTruth{}, g.Events...)
	other.Events[2].Target = "/usr/bin/codex exec"
	for name, c := range map[string]models.GroundTruthFile{"no launcher script": noScript, "another binary": other} {
		if pid := (Adapter{}).HarnessProcess(c); pid != 0 {
			t.Errorf("%s: harness %d", name, pid)
		}
	}
}

// The model traffic of 0.166.0 is declared housekeeping (I-89): the
// upgrade GET of the model endpoint without a body and each client message
// on the WebSocket with one, at the exact host and path; nothing else, and
// nothing for another version.
func TestHousekeepingIsTheModelTrafficOnly(t *testing.T) {
	h := "sha256:00"
	req := func(target string, body bool) models.GroundTruthEvent {
		e := models.GroundTruthEvent{ActionType: models.NetRequest, Target: target}
		if body {
			e.RequestHash = &h
		}
		return e
	}
	p := agent.HarnessHousekeeping(Adapter{}, "0.166.0")
	if p == nil {
		t.Fatal("no declaration for 0.166.0")
	}
	for _, c := range []struct {
		e    models.GroundTruthEvent
		want bool
	}{
		{req("GET https://chatgpt.com/backend-api/codex/responses", false), true},
		{req("WS https://chatgpt.com/backend-api/codex/responses", true), true},
		{req("GET https://chatgpt.com/backend-api/codex/responses", true), false},
		{req("WS https://chatgpt.com/backend-api/codex/responses", false), false},
		{req("POST https://chatgpt.com/backend-api/codex/responses", true), false},
		{req("WS https://chatgpt.com/backend-api/codex/other", true), false},
		{req("WS https://chatgpt.com/backend-api/codex/responses?x=1", true), false},
		{req("WS https://evil.example/backend-api/codex/responses", true), false},
		{req("GET https://chatgpt.com/", false), false},
		{models.GroundTruthEvent{ActionType: models.NetConnect, Target: "chatgpt.com"}, false},
		{models.GroundTruthEvent{ActionType: models.NetRequest, Target: "WS https://chatgpt.com/backend-api/codex/responses", RequestHash: &h, TargetTruncated: true}, false},
	} {
		if got := p(c.e); got != c.want {
			t.Errorf("%s %s (body %v): %v, want %v", c.e.ActionType, c.e.Target, c.e.RequestHash != nil, got, c.want)
		}
	}
	if agent.HarnessHousekeeping(Adapter{}, "0.167.0") != nil {
		t.Error("another version declares housekeeping")
	}
}
