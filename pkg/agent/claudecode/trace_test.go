package claudecode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The declaration names the workspace's project directory as the harness
// spells it (I-70), each session's transcript and everything under its
// subagents directory, and nothing else of the project (I-74).
func TestTraceDeclaresTheSessionTranscriptsAndSubagents(t *testing.T) {
	const id = "0c9360d8-5b62-41d4-9a06-0767bdea7f3a"
	d := Adapter{}.Trace("/tmp/cap_1.2/ws-task", "/home/u")
	proj := "/home/u/.claude/projects/-tmp-cap-1-2-ws-task/"
	for path, want := range map[string][2]bool{ // covers, main
		proj + id + ".jsonl":                                             {true, true},
		proj + id + "/subagents":                                         {true, false},
		proj + id + "/subagents/agent-a0123456789abcdef.jsonl":           {true, false},
		proj + id + "/subagents/agent-a1.meta.json":                      {true, false},
		proj + id + "/tool-results/x.txt":                                {false, false},
		proj + "memory/MEMORY.md":                                        {false, false},
		proj + id + ".jsonl.bak":                                         {false, false},
		proj + "not-a-uuid.jsonl":                                        {false, false},
		"/home/u/.claude/projects/-tmp-other/" + id + ".jsonl":           {false, false},
		"/home/v/.claude/projects/-tmp-cap-1-2-ws-task/" + id + ".jsonl": {false, false},
		proj + id + ".jsonl (deleted)":                                   {false, false},
	} {
		if got := [2]bool{d.Covers(path), d.Main(path)}; got != want {
			t.Errorf("%s: covers, main = %v, want %v", path, got, want)
		}
	}
	// Without a recorded home, any home I-30 declares.
	d = Adapter{}.Trace("/ws/tools", "")
	if !d.Main("/root/.claude/projects/-ws-tools/"+id+".jsonl") || !d.Main("/home/x/.claude/projects/-ws-tools/"+id+".jsonl") {
		t.Error("without a home, the transcript under any home should be declared")
	}
	// A name over 200 characters is matched as the harness cuts it.
	long := "/" + strings.Repeat("a", 230)
	d = Adapter{}.Trace(long, "/home/u")
	cut := "-" + strings.Repeat("a", 199)
	if !d.Main("/home/u/.claude/projects/"+cut+"-1x2y3z/"+id+".jsonl") || d.Main("/home/u/.claude/projects/-"+strings.Repeat("a", 230)+"/"+id+".jsonl") {
		t.Error("a long workspace should be matched as its cut name and hash")
	}
	for _, ws := range []string{"", "relative/ws", "/ws/../x"} {
		if (Adapter{}).Trace(ws, "/home/u") != nil {
			t.Errorf("workspace %q: want no declaration", ws)
		}
	}
	if (Adapter{}).Trace("/ws", "/etc") != nil {
		t.Error("a home I-30 does not declare: want no declaration")
	}
}

func tools306TraceInput(t *testing.T, g models.GroundTruthFile, extra models.GroundTruth) verification.Input {
	t.Helper()
	tr, _, err := Adapter{}.Parse(filepath.Join(tools306Dir, "tools.session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	g.Events = append(append(models.GroundTruth{}, g.Events...), extra...)
	b, err := agent.Capture(Adapter{}, "2.1.306", tools306Controls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}})
	if err != nil {
		t.Fatal(err)
	}
	in := agent.PrepareWithBaseline(Adapter{}, tr, g, &b, verification.Options{IntervalSlack: 500 * time.Millisecond})
	in.Trace.Decl = agent.Trace(Adapter{}, g)
	return in
}

// On the 2.1.306 tools capture the declaration finds the harness's own
// writing of the transcript and of the subagent's files, all by its own
// process, so nothing is tampering and the verdict is the one without the
// declaration.
func TestTools306TheHarnessWritingItsTraceIsNoTampering(t *testing.T) {
	g := tools306Run(t, "tools")
	in := tools306TraceInput(t, g, nil)
	v := verification.Verify(in)
	if len(v.TraceTampering) != 0 {
		t.Fatalf("tampering %+v, want none", v.TraceTampering)
	}
	if len(v.Trace.Files) != 1 || v.Trace.Files[0].Last == nil || v.Trace.Files[0].Last.ActionType != models.FileClose || v.Trace.Files[0].Last.OutputHash == nil {
		t.Fatalf("trace files %+v, want the transcript with a hashed last close", v.Trace.Files)
	}
	in.Trace.Decl = nil
	without := verification.Verify(in)
	if v.Outcome != without.Outcome || v.Findings() != without.Findings() || len(v.Reasons) != len(without.Reasons) {
		t.Errorf("with the declaration %v/%d, without %v/%d", v.Outcome, v.Findings(), without.Outcome, without.Findings())
	}
}

// A Bash command that deletes the transcript, added to the real capture,
// is tampering after the adapter's normalization, and the run is NOT
// FAITHFUL; so is a claimed Write of the transcript.
func TestTools306ACommandDeletingTheTranscriptIsTampering(t *testing.T) {
	g := tools306Run(t, "tools")
	var transcript string
	var last time.Time
	for _, e := range g.Events {
		if strings.HasSuffix(e.Target, ".jsonl") && strings.Contains(e.Target, "/.claude/projects/") && !strings.Contains(e.Target, "/subagents/") {
			transcript = e.Target
		}
		if e.Timestamp.After(last) {
			last = e.Timestamp
		}
	}
	if transcript == "" {
		t.Fatal("no transcript event in the capture")
	}
	at := func(ms int) time.Time { return last.Add(time.Duration(ms) * time.Millisecond) }
	const shell = "/bin/bash -c rm transcript"
	extra := models.GroundTruth{
		{Timestamp: at(1), ActionType: models.ProcessFork, Target: "x", PID: 990001, PPID: g.RootPID},
		{Timestamp: at(2), ActionType: models.ProcessExec, Target: shell, PID: 990001, PPID: g.RootPID},
		{Timestamp: at(3), ActionType: models.FileDelete, Target: transcript + " (deleted)", PID: 990001},
		{Timestamp: at(4), ActionType: models.ProcessExit, Target: shell, PID: 990001, PPID: g.RootPID},
	}
	v := verification.Verify(tools306TraceInput(t, g, extra))
	if v.Outcome != verification.OutcomeNotFaithful || len(v.TraceTampering) != 1 || v.TraceTampering[0].Event.Target != transcript {
		t.Fatalf("outcome %v, tampering %+v, want NOT FAITHFUL with the delete", v.Outcome, v.TraceTampering)
	}
	in := tools306TraceInput(t, g, nil)
	in.Claims = append(in.Claims, models.TrajectoryEntry{Timestamp: at(1), ActionType: models.FileWrite, Target: transcript, Tool: toolWrite})
	v = verification.Verify(in)
	if v.Outcome != verification.OutcomeNotFaithful || len(v.TraceTampering) != 1 || v.TraceTampering[0].Claim == nil {
		t.Fatalf("outcome %v, tampering %+v, want NOT FAITHFUL with the claim", v.Outcome, v.TraceTampering)
	}
}

// ReadTrace reads a missing, empty or damaged transcript as a trace that
// cannot be verified, never as an error, and hashes an intact one on
// request (V-59).
func TestReadTraceFailsClosed(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.jsonl")
	garbled := filepath.Join(dir, "garbled.jsonl")
	_ = os.WriteFile(empty, nil, 0o644)
	_ = os.WriteFile(garbled, []byte("{not json\n"), 0o644)
	for path, want := range map[string]verification.TraceState{
		filepath.Join(dir, "gone.jsonl"): verification.TraceMissing,
		empty:                            verification.TraceEmpty,
		garbled:                          verification.TraceDamaged,
	} {
		_, _, in, err := agent.ReadTrace(Adapter{}, path, true)
		if err != nil || in.State != want || in.Detail == "" || in.ReadHash != "" {
			t.Errorf("%s: state %q detail %q hash %q err %v, want %q", filepath.Base(path), in.State, in.Detail, in.ReadHash, err, want)
		}
	}
	session := filepath.Join(tools306Dir, "tools.session.jsonl")
	tr, _, in, err := agent.ReadTrace(Adapter{}, session, true)
	want, _ := content.SHA256File(session)
	if err != nil || in.State != verification.TraceRead || in.ReadHash != want || len(tr) == 0 {
		t.Errorf("intact: state %q hash %q err %v, %d claims", in.State, in.ReadHash, err, len(tr))
	}
	if _, _, in, _ := agent.ReadTrace(Adapter{}, session, false); in.ReadHash != "" {
		t.Error("without a request the file should not be hashed")
	}
}
