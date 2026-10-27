package claudecode

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/config"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// grepSession writes a transcript of one Grep call with the given input and
// working directories, and parses it.
func grepSession(t *testing.T, version, input, useCwd, resultCwd string, withResult bool) models.Trajectory {
	t.Helper()
	cwd := func(c string) string {
		if c == "" {
			return ""
		}
		return fmt.Sprintf(`,"cwd":%q`, c)
	}
	lines := fmt.Sprintf(`{"type":"assistant","timestamp":"2026-10-26T10:00:00Z","sessionId":"s","version":%q%s,"message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"Grep","input":%s}]}}`, version, cwd(useCwd), input) + "\n"
	if withResult {
		lines += fmt.Sprintf(`{"type":"user","timestamp":"2026-10-26T10:00:01Z","sessionId":"s","version":%q%s,"message":{"id":"m2","content":[{"type":"tool_result","tool_use_id":"t1","content":"No matches found"}]},"toolUseResult":{"mode":"content","numFiles":0,"filenames":[],"content":"","numLines":0}}`, version, cwd(resultCwd)) + "\n"
	}
	p := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(p, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, rep, err := Adapter{}.Parse(p)
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("parse: %v %v", err, rep.ParseErrors)
	}
	return tr
}

// A Grep that names a path gets one harness-implied open of it, resolved
// against the session's working directory and marked as coming before the
// search (I-69, V-48); no path, an unknown or changed working directory, a
// path from the home directory, a missing result and an unchecked version
// derive none.
func TestAGrepOfAPathImpliesTheHarnessOpenBeforeTheSearch(t *testing.T) {
	file := `{"pattern":"NotImplementedError","path":"textkit/strings.py","output_mode":"content"}`
	for name, tc := range map[string]struct {
		version, input, useCwd, resCwd string
		noResult                       bool
		want                           string
	}{
		"a relative path":               {"2.1.306", file, "/ws", "/ws", false, "/ws/textkit/strings.py"},
		"a directory, also claimed":     {"2.1.306", `{"pattern":"x","path":"textkit"}`, "/ws", "/ws", false, "/ws/textkit"},
		"an absolute path":              {"2.1.306", `{"pattern":"x","path":"/etc/./hosts"}`, "/ws", "/ws", false, "/etc/hosts"},
		"on 2.1.296":                    {"2.1.296", file, "/ws", "/ws", false, "/ws/textkit/strings.py"},
		"on 2.1.286, binary not read":   {"2.1.286", file, "/ws", "/ws", false, ""},
		"on an unchecked version":       {"2.1.300", file, "/ws", "/ws", false, ""},
		"no path":                       {"2.1.306", `{"pattern":"x"}`, "/ws", "/ws", false, ""},
		"a path from home":              {"2.1.306", `{"pattern":"x","path":"~/notes.txt"}`, "/ws", "/ws", false, ""},
		"no working directory":          {"2.1.306", file, "", "", false, ""},
		"a relative working directory":  {"2.1.306", file, "ws", "ws", false, ""},
		"the working directory changed": {"2.1.306", file, "/ws", "/ws/sub", false, ""},
		"no result":                     {"2.1.306", file, "/ws", "/ws", true, ""},
	} {
		t.Run(name, func(t *testing.T) {
			tr := grepSession(t, tc.version, tc.input, tc.useCwd, tc.resCwd, !tc.noResult)
			if tr[0].ActionType != models.ProcessExec || tr[0].Target != SearchGrep || tr[0].ImpliedBy != "" {
				t.Fatalf("first claim %+v, want the Grep's own", tr[0])
			}
			if tc.want == "" {
				if len(tr) != 1 {
					t.Errorf("claims %+v, want the Grep claim alone", tr)
				}
				return
			}
			if len(tr) != 2 {
				t.Fatalf("claims %+v, want the Grep claim and one implied open", tr)
			}
			e := tr[1]
			if e.ActionType != models.FileOpen || e.Target != tc.want || e.ImpliedBy != SearchGrep || !e.ImpliedBefore || e.Tool != toolGrep ||
				!e.Timestamp.Equal(tr[0].Timestamp) || e.End == nil || tr[0].End == nil || !e.End.Equal(*tr[0].End) || e.InputHash != nil {
				t.Errorf("implied claim %+v, want an open of %s before %q over the call's interval", e, tc.want, SearchGrep)
			}
		})
	}
}

// End to end, in the shape of a long task on 2.1.306: the agent's process
// opens the file a Grep names, then starts its embedded ripgrep on
// /proc/self/fd/3, which the probe sees opening the same file. The open is
// explained as the harness's and the run is FAITHFUL; without the derived
// claim it is an Unrecorded finding. A Grep over a directory adds nothing to
// explain and its implied claim stays unpaired, at no cost.
func TestTheHarnessOpenBeforeAGrepIsExplainedEndToEnd(t *testing.T) {
	const root = 100
	ts := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	at := func(ms int) time.Time { return ts.Add(time.Duration(ms) * time.Millisecond) }
	ev := func(ms int, typ models.ActionType, target string, pid, ppid uint32) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at(ms), ActionType: typ, Target: target, PID: pid, PPID: ppid}
	}
	rg := func(target string) string {
		return "/home/u/.local/share/claude/versions/2.1.306 --no-config --hidden --glob !.git --max-columns 500 --json -n NotImplementedError " + target
	}
	g := models.GroundTruthFile{RootPID: root, Workspace: "/ws", Coverage: &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}}, Events: models.GroundTruth{
		ev(10, models.ProcessFork, "x", 201, root), ev(11, models.ProcessExec, rg("."), 201, root),
		ev(12, models.FileOpen, "/ws/textkit/a.py", 201, 0), ev(13, models.FileOpen, "/ws/textkit/b.py", 201, 0),
		ev(14, models.ProcessExit, rg("."), 201, root),
		ev(1010, models.FileOpen, "/ws/textkit/a.py", root, 0),
		ev(1011, models.ProcessFork, "x", 202, root), ev(1012, models.ProcessExec, rg("/proc/self/fd/3"), 202, root),
		ev(1016, models.FileOpen, "/ws/textkit/a.py", 202, 0),
		ev(1017, models.ProcessExit, rg("/proc/self/fd/3"), 202, root),
	}}
	call := func(ms int, id, input string) string {
		return fmt.Sprintf(`{"type":"assistant","timestamp":%q,"sessionId":"s","version":"2.1.306","cwd":"/ws","message":{"id":"m%s","content":[{"type":"tool_use","id":%q,"name":"Grep","input":%s}]}}`, at(ms).Format(time.RFC3339Nano), id, id, input) + "\n" +
			fmt.Sprintf(`{"type":"user","timestamp":%q,"sessionId":"s","version":"2.1.306","cwd":"/ws","message":{"id":"r%s","content":[{"type":"tool_result","tool_use_id":%q,"content":"(out)"}]}}`, at(ms+50).Format(time.RFC3339Nano), id, id)
	}
	lines := call(0, "t1", `{"pattern":"NotImplementedError","path":"textkit","output_mode":"content"}`) + "\n" +
		call(1000, "t2", `{"pattern":"NotImplementedError","path":"textkit/a.py","output_mode":"content"}`) + "\n"
	p := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(p, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, _, err := Adapter{}.Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	v := verification.Verify(agent.Prepare(Adapter{}, tr, g, nil, verification.Options{IntervalSlack: 500 * time.Millisecond}))
	if v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 2 || len(v.HarnessImplied) != 1 || v.HarnessImplied[0].Event.PID != root ||
		len(v.HarnessImpliedUnpaired) != 1 || v.HarnessImpliedUnpaired[0].Target != "/ws/textkit" {
		t.Fatalf("outcome %s, corroborated %d, implied %v, unpaired %v, unrecorded %v, reasons %v", v.Outcome, len(v.Corroborated), v.HarnessImplied, v.HarnessImpliedUnpaired, v.Unrecorded, v.Reasons)
	}
	var ordinary models.Trajectory
	for _, e := range tr {
		if e.ImpliedBy == "" {
			ordinary = append(ordinary, e)
		}
	}
	v = verification.Verify(agent.Prepare(Adapter{}, ordinary, g, nil, verification.Options{IntervalSlack: 500 * time.Millisecond}))
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != "/ws/textkit/a.py" {
		t.Errorf("without the implied claim: outcome %s, unrecorded %v", v.Outcome, v.Unrecorded)
	}
}

// grepOpenNotGated are configured versions without I-69's rule, each with why.
var grepOpenNotGated = map[string]string{
	"2.1.286": "its binary was not read for I-69, and its one captured Grep names no path",
}

// TestGrepOpenGateAgreesWithTheConfig ties I-69's gate to config/agents.json
// (I-57): every configured version has the rule or is explained above, and
// every gated version is configured.
func TestGrepOpenGateAgreesWithTheConfig(t *testing.T) {
	c, err := config.Load(filepath.Join("..", "..", "..", config.RelPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range c.Versions(Name) {
		_, explained := grepOpenVersions[v]
		if _, skip := grepOpenNotGated[v]; !explained && !skip {
			t.Errorf("configured version %s is not in grepOpenVersions (I-69): read its Grep tool before configuring it, or explain it", v)
		}
	}
	gated := make([]string, 0, len(grepOpenVersions))
	for v := range grepOpenVersions {
		gated = append(gated, v)
	}
	sort.Strings(gated)
	for _, v := range gated {
		if !c.Configured(Name, v) {
			t.Errorf("grepOpenVersions has %s, which is not configured", v)
		}
	}
}
