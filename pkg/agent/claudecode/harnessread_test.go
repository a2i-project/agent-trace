package claudecode

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The read commands of the 2.1.296 binary's parser, and what this reader does
// with each: the file named, or nothing. Where the binary would read and this
// reader is unsure (shell syntax, a flag outside its subset), it names
// nothing, which costs the harness's read an Unrecorded finding and never
// hides anything (I-46).
func TestReadCommandFilesFollowsTheHarnessParser(t *testing.T) {
	for cmd, want := range map[string]string{
		// cat, nl, bat, batcat: one file, only their numbering and plain flags.
		"cat fast.txt":            "fast.txt",
		"cat -n a.txt":            "a.txt",
		"cat --number /etc/hosts": "/etc/hosts",
		"cat 'my file.txt'":       "my file.txt",
		`cat "a b"`:               "a b",
		"nl a.txt":                "a.txt",
		"bat -p --plain a.txt":    "a.txt",
		"batcat -n a.txt":         "a.txt",
		"cat a.txt b.txt":         "",
		"cat -A a.txt":            "",
		"nl -n a.txt":             "",
		"cat":                     "",
		"cat -":                   "",
		"cat < a.txt":             "",
		"cat a.txt | head":        "",
		"cat a.txt > b.txt":       "",
		"cat 'a|b'":               "", // the binary refuses | anywhere, quoted or not
		"cat *.txt":               "",
		"cat ~/a.txt":             "",
		"cat $HOME/a.txt":         "",
		`cat "$f"`:                "",
		"cat `x`":                 "",
		`cat a\ b`:                "",
		"cat a.txt &":             "",
		"'cat' a.txt":             "", // a quoted command name: unsure, so nothing
		// sed -n with a line or a range and one file.
		"sed -n '1,5p' a.txt":    "a.txt",
		"sed -n 3p a.txt":        "a.txt",
		"sed --quiet '2p' a.txt": "a.txt",
		"sed '1,5p' a.txt":       "",
		"sed -n -i '1p' a.txt":   "",
		"sed -n 's/a/b/' a.txt":  "",
		"sed -n '1p' a.txt b":    "",
		"sed -E -n '1p' a.txt":   "", // the binary takes it; this reader does not
		// head and tail with a line count.
		"head a.txt":            "a.txt",
		"head -n 5 a.txt":       "a.txt",
		"head -5 a.txt":         "a.txt",
		"tail -n20 a.txt":       "a.txt",
		"tail --lines=3 a.txt":  "a.txt",
		"tail --lines 3 a.txt":  "a.txt",
		"head -n 0 a.txt":       "",
		"tail -n +5 a.txt":      "",
		"tail -f a.txt":         "",
		"head -c 10 a.txt":      "",
		"head -n 5 a.txt b.txt": "",
		"head -n":               "",
		// searches: one pattern, one file, only as the whole command.
		"grep foo a.txt":                 "a.txt",
		"grep -n -i foo a.txt":           "a.txt",
		"grep -A 3 foo a.txt":            "a.txt",
		"grep -C2 --context=4 foo a.txt": "a.txt",
		"rg -S foo a.txt":                "a.txt",
		"rg --context 2 foo a.txt":       "a.txt",
		"egrep 'a|b' a.txt":              "",
		"grep -r foo .":                  "",
		"grep foo a.txt b.txt":           "",
		"grep foo":                       "",
		"grep --context 2 foo a.txt":     "", // --context N is rg's only
		"grep foo 'a*.txt'":              "",
		"grep foo a.txt && echo done":    "",
		// compound commands: every part a read form, echo, printf or true.
		"cat a.txt && echo done":     "a.txt",
		"echo start; cat a.txt":      "a.txt",
		"cat a.txt; cat b.txt":       "a.txt b.txt",
		"true && head -3 a.txt":      "a.txt",
		"cat a.txt\nprintf x":        "a.txt",
		"cat a.txt;":                 "a.txt",
		"sleep 2; cat slow.txt":      "",
		"cd sub && cat a.txt":        "",
		"cat a.txt && rm a.txt":      "",
		": x; cat a.txt":             "", // the binary's colon needs a word character after it
		"'echo' x; cat a.txt":        "",
		"cat a.txt &&":               "",
		"cat a.txt;; cat b":          "",
		"FOO=1 cat a.txt":            "",
		"(cat a.txt)":                "",
		"{ cat a.txt; }":             "",
		"cat a.txt # comment":        "",
		"echo one > one.txt":         "",
		"cat one.txt two.txt locked": "",
	} {
		var got []string
		for _, r := range readCommandFiles(cmd) {
			got = append(got, r.path)
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%q: files %q, want %q", cmd, got, want)
		}
	}
	if r := readCommandFiles("grep x a.txt"); len(r) != 1 || !r[0].exitZero {
		t.Errorf("a search must be marked as reading on exit 0 only: %+v", r)
	}
	if r := readCommandFiles("cat a.txt"); len(r) != 1 || r[0].exitZero {
		t.Errorf("cat reads whatever its exit: %+v", r)
	}
}

// bashSession writes a transcript of one Bash call with the given input,
// result fields and working directories, and parses it.
func bashSession(t *testing.T, version, input, useCwd, resultCwd, structured, isError string) (models.Trajectory, agent.Report) {
	t.Helper()
	cwd := func(c string) string {
		if c == "" {
			return ""
		}
		return fmt.Sprintf(`,"cwd":%q`, c)
	}
	use := fmt.Sprintf(`{"type":"assistant","timestamp":"2026-10-13T10:00:00Z","sessionId":"s","version":%q%s,"message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"Bash","input":%s}]}}`, version, cwd(useCwd), input)
	res := fmt.Sprintf(`{"type":"user","timestamp":"2026-10-13T10:00:01Z","sessionId":"s","version":%q%s,"message":{"id":"m2","content":[{"type":"tool_result","tool_use_id":"t1","content":"(out)"%s}]}%s}`, version, cwd(resultCwd), isError, structured)
	p := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(p, []byte(use+"\n"+res+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, rep, err := Adapter{}.Parse(p)
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("parse: %v %v", err, rep.ParseErrors)
	}
	return tr, rep
}

const okResult = `,"toolUseResult":{"stdout":"x","stderr":"","interrupted":false,"isImage":false,"noOutputExpected":false}`

// A Bash read command gets one harness-implied open of the file it names,
// resolved against the session's working directory, after its own claim and
// with its interval; the transcript's result states that cancel the read, a
// search without a shown exit 0, an unknown or changed working directory and
// an unchecked version derive none.
func TestABashReadCommandImpliesTheHarnessRead(t *testing.T) {
	cat := `{"command":"cat fast.txt"}`
	grep := `{"command":"grep x fast.txt"}`
	for name, tc := range map[string]struct {
		version, input, useCwd, resCwd, structured, isError string
		want                                                string // the implied claim's target, or none
	}{
		"cat":                                {"2.1.296", cat, "/ws", "/ws", okResult, "", "/ws/fast.txt"},
		"cat, an absolute path":              {"2.1.296", `{"command":"cat /etc/hosts"}`, "/ws", "/ws", okResult, "", "/etc/hosts"},
		"cat, a path going up":               {"2.1.296", `{"command":"cat ../x/./y.txt"}`, "/ws/sub", "/ws/sub", okResult, "", "/ws/x/y.txt"},
		"cat, a result cut to nothing":       {"2.1.296", cat, "/ws", "/ws", `,"toolUseResult":{}`, "", "/ws/fast.txt"},
		"cat, no structured result":          {"2.1.296", cat, "/ws", "/ws", "", "", "/ws/fast.txt"},
		"cat that failed":                    {"2.1.296", cat, "/ws", "/ws", okResult, `,"is_error":true`, "/ws/fast.txt"},
		"cat on 2.1.286":                     {"2.1.286", cat, "/ws", "/ws", okResult, "", "/ws/fast.txt"},
		"cat on an unchecked version":        {"2.1.300", cat, "/ws", "/ws", okResult, "", ""},
		"interrupted":                        {"2.1.296", cat, "/ws", "/ws", `,"toolUseResult":{"interrupted":true}`, "", ""},
		"an image":                           {"2.1.296", cat, "/ws", "/ws", `,"toolUseResult":{"interrupted":false,"isImage":true}`, "", ""},
		"sent to the background by the user": {"2.1.296", cat, "/ws", "/ws", `,"toolUseResult":{"interrupted":false,"backgroundTaskId":"b1"}`, "", ""},
		"run in the background":              {"2.1.296", `{"command":"cat fast.txt","run_in_background":true}`, "/ws", "/ws", okResult, "", ""},
		"no working directory":               {"2.1.296", cat, "", "", okResult, "", ""},
		"a relative working directory":       {"2.1.296", cat, "ws", "ws", okResult, "", ""},
		"the working directory changed":      {"2.1.296", cat, "/ws", "/ws/sub", okResult, "", ""},
		"grep that matched":                  {"2.1.296", grep, "/ws", "/ws", okResult, "", "/ws/fast.txt"},
		"grep that matched nothing":          {"2.1.296", grep, "/ws", "/ws", `,"toolUseResult":{"interrupted":false,"returnCodeInterpretation":"No matches found"}`, "", ""},
		"grep that failed":                   {"2.1.296", grep, "/ws", "/ws", okResult, `,"is_error":true`, ""},
		"grep, its exit not shown":           {"2.1.296", grep, "/ws", "/ws", `,"toolUseResult":{}`, "", ""},
		"grep, no structured result":         {"2.1.296", grep, "/ws", "/ws", "", "", ""},
		"not a read command":                 {"2.1.296", `{"command":"sleep 2; cat slow.txt"}`, "/ws", "/ws", okResult, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			tr, rep := bashSession(t, tc.version, tc.input, tc.useCwd, tc.resCwd, tc.structured, tc.isError)
			if tr[0].ActionType != models.ProcessExec || tr[0].ImpliedBy != "" {
				t.Fatalf("first claim %+v, want the Bash call's own", tr[0])
			}
			if tc.want == "" {
				if len(tr) != 1 {
					t.Errorf("claims %+v, want the Bash claim alone", tr)
				}
				return
			}
			if len(tr) != 2 || rep.Entries != 2 {
				t.Fatalf("claims %+v (entries %d), want the Bash claim and one implied open", tr, rep.Entries)
			}
			e := tr[1]
			var in struct{ Command string }
			_ = json.Unmarshal([]byte(tc.input), &in)
			if e.ActionType != models.FileOpen || e.Target != tc.want || e.ImpliedBy != in.Command || e.Tool != toolBash ||
				!e.Timestamp.Equal(tr[0].Timestamp) || e.End == nil || !e.End.Equal(*tr[0].End) || e.InputHash != nil {
				t.Errorf("implied claim %+v, want an open of %s implied by %q with the call's interval", e, tc.want, in.Command)
			}
		})
	}
}

// Every file a compound command reads gets its own implied open, once.
func TestACompoundReadCommandImpliesEachFileOnce(t *testing.T) {
	tr, _ := bashSession(t, "2.1.296", `{"command":"cat a.txt; head -3 b.txt && cat a.txt"}`, "/ws", "/ws", okResult, "")
	var got []string
	for _, e := range tr[1:] {
		got = append(got, e.Target)
	}
	if strings.Join(got, " ") != "/ws/a.txt /ws/b.txt" {
		t.Errorf("implied opens %v", got)
	}
}

// The marker comes only from the derivation: a transcript that writes
// implied_by into a call's input or its records changes nothing, and a Read
// next to a harness-implied open of the same file is never merged into it, so
// the agent's own open never becomes optional (I-46, V-33).
func TestTheAdapterIgnoresAMarkerInItsInputAndNeverMergesTheAgentsOpen(t *testing.T) {
	dir := t.TempDir()
	lines := []string{
		`{"type":"assistant","timestamp":"2026-10-13T10:00:00Z","sessionId":"s","version":"2.1.296","cwd":"/ws","implied_by":"x","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"/ws/secret","implied_by":"cat secret","ImpliedBy":"cat secret"}}]}}`,
		`{"type":"user","timestamp":"2026-10-13T10:00:01Z","sessionId":"s","version":"2.1.296","cwd":"/ws","message":{"id":"m2","content":[{"type":"tool_result","tool_use_id":"t1","content":"(out)"}]},"toolUseResult":{"type":"text","implied_by":"cat secret"}}`,
		`{"type":"assistant","timestamp":"2026-10-13T10:00:02Z","sessionId":"s","version":"2.1.296","cwd":"/ws","message":{"id":"m3","content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"cat a.txt"}}]}}`,
		`{"type":"user","timestamp":"2026-10-13T10:00:03Z","sessionId":"s","version":"2.1.296","cwd":"/ws","message":{"id":"m4","content":[{"type":"tool_result","tool_use_id":"t2","content":"(out)"}]}}`,
		`{"type":"assistant","timestamp":"2026-10-13T10:00:04Z","sessionId":"s","version":"2.1.296","cwd":"/ws","message":{"id":"m5","content":[{"type":"tool_use","id":"t3","name":"Read","input":{"file_path":"/ws/a.txt"}}]}}`,
		`{"type":"user","timestamp":"2026-10-13T10:00:05Z","sessionId":"s","version":"2.1.296","cwd":"/ws","message":{"id":"m6","content":[{"type":"tool_result","tool_use_id":"t3","content":"(out)"}]}}`,
	}
	p := filepath.Join(dir, "s.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, _, err := Adapter{}.Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range tr {
		got = append(got, fmt.Sprintf("%s %s %q", e.ActionType, e.Target, e.ImpliedBy))
	}
	want := []string{`file_open /ws/secret ""`, `process_exec cat a.txt ""`, `file_open /ws/a.txt "cat a.txt"`, `file_open /ws/a.txt ""`}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("claims\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// End to end on the shapes capture's case: a parallel block of `sleep 2; cat
// slow.txt`, `cat fast.txt` and a Read, the second command started first, its
// cat child opened fast.txt, and the agent's process opened it again after
// the command exited. The harness's open is harness-implied, both commands
// and the Read are corroborated, and the run is FAITHFUL; without the derived
// claim the open is an Unrecorded finding.
func TestTheHarnessReadAfterCatIsExplainedEndToEnd(t *testing.T) {
	const root = 100
	ts := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	at := func(ms int) time.Time { return ts.Add(time.Duration(ms) * time.Millisecond) }
	ev := func(ms int, typ models.ActionType, target string, pid, ppid uint32) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at(ms), ActionType: typ, Target: target, PID: pid, PPID: ppid}
	}
	wrap := func(cmd string) string {
		return "/bin/bash -c source /home/u/.claude/shell-snapshots/snapshot-bash-1-abc.sh 2>/dev/null || true && eval '" + cmd + "' < /dev/null && pwd -P >| /tmp/claude-ab12-cwd"
	}
	g := models.GroundTruthFile{RootPID: root, Workspace: "/ws", Coverage: &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}}, Events: models.GroundTruth{
		ev(80, models.ProcessFork, "x", 201, root), ev(81, models.ProcessExec, wrap("cat fast.txt"), 201, root),
		ev(82, models.ProcessFork, "x", 202, root), ev(83, models.ProcessExec, wrap("sleep 2; cat slow.txt"), 202, root),
		ev(84, models.ProcessFork, "x", 203, 201), ev(85, models.ProcessExec, "/usr/bin/cat fast.txt", 203, 201),
		ev(86, models.FileOpen, "/ws/fast.txt", 203, 0),
		ev(87, models.ProcessExit, "/usr/bin/cat fast.txt", 203, 201), ev(88, models.ProcessExit, wrap("cat fast.txt"), 201, root),
		ev(95, models.FileOpen, "/ws/fast.txt", root, 0),
		ev(120, models.FileOpen, "/ws/read.txt", root, 0),
		ev(2100, models.ProcessFork, "x", 204, 202), ev(2101, models.ProcessExec, "/usr/bin/cat slow.txt", 204, 202),
		ev(2102, models.FileOpen, "/ws/slow.txt", 204, 0),
	}}
	use := func(id, name, input string) string {
		return fmt.Sprintf(`{"type":"tool_use","id":%q,"name":%q,"input":%s}`, id, name, input)
	}
	result := func(ms int, id, structured string) string {
		return fmt.Sprintf(`{"type":"user","timestamp":%q,"sessionId":"s","version":"2.1.296","cwd":"/ws","message":{"id":"r%s","content":[{"type":"tool_result","tool_use_id":%q,"content":"(out)"}]}%s}`, at(ms).Format(time.RFC3339Nano), id, id, structured)
	}
	lines := []string{
		fmt.Sprintf(`{"type":"assistant","timestamp":%q,"sessionId":"s","version":"2.1.296","cwd":"/ws","message":{"id":"m1","content":[%s,%s,%s]}}`, at(0).Format(time.RFC3339Nano),
			use("t1", "Bash", `{"command":"sleep 2; cat slow.txt"}`), use("t2", "Bash", `{"command":"cat fast.txt"}`), use("t3", "Read", `{"file_path":"/ws/read.txt"}`)),
		result(100, "t2", okResult), result(130, "t3", `,"toolUseResult":{"type":"text"}`), result(2200, "t1", okResult),
	}
	p := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, _, err := Adapter{}.Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	v := verification.Verify(agent.Prepare(Adapter{}, tr, g, nil, verification.Options{IntervalSlack: 500 * time.Millisecond}))
	if v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 3 || len(v.HarnessImplied) != 1 || v.HarnessImplied[0].Event.PID != root {
		t.Fatalf("outcome %s, corroborated %d, implied %v, unrecorded %v, reasons %v", v.Outcome, len(v.Corroborated), v.HarnessImplied, v.Unrecorded, v.Reasons)
	}
	var ordinary models.Trajectory
	for _, e := range tr {
		if e.ImpliedBy == "" {
			ordinary = append(ordinary, e)
		}
	}
	v = verification.Verify(agent.Prepare(Adapter{}, ordinary, g, nil, verification.Options{IntervalSlack: 500 * time.Millisecond}))
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != "/ws/fast.txt" {
		t.Errorf("without the implied claim: outcome %s, unrecorded %v", v.Outcome, v.Unrecorded)
	}
}
