package claudecode

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const (
	cpSession = "dfec52da-0000-4000-8000-000000000001"
	cpOther   = "dfec52da-0000-4000-8000-000000000002"
)

// cpName is the base name 2.1.306 gives version n of a file's checkpoint.
func cpName(file, n string) string {
	sum := sha256.Sum256([]byte(file))
	return hex.EncodeToString(sum[:])[:16] + "@v" + n
}

// V-104: the declaration names a file's versions in the session's own
// checkpoint directory under the capture's home, for 2.1.306 only.
func TestDeclareCheckpointNamesTheSessionsVersionsOfTheFile(t *testing.T) {
	const file = "/ws/textkit/strings.py"
	dir := "/home/u/.claude/file-history/" + cpSession + "/"
	cp := declareCheckpoint("/home/u", cpSession, "2.1.306")
	if cp == nil {
		t.Fatal("no declaration for 2.1.306")
	}
	for _, c := range []struct {
		file, written string
		want          bool
	}{
		{file, dir + cpName(file, "1"), true},
		{file, dir + cpName(file, "2"), true},
		{file, dir + cpName(file, "17"), true},
		// Another file's hash, another session, another home, another
		// directory, a malformed version.
		{file, dir + cpName("/ws/textkit/numbers.py", "2"), false},
		{file, "/home/u/.claude/file-history/" + cpOther + "/" + cpName(file, "2"), false},
		{file, "/home/v/.claude/file-history/" + cpSession + "/" + cpName(file, "2"), false},
		{file, "/home/u/.claude/backups/" + cpSession + "/" + cpName(file, "2"), false},
		{file, dir + "x/" + cpName(file, "2"), false},
		{file, dir + cpName(file, "0"), false},
		{file, dir + cpName(file, "02"), false},
		{file, dir + cpName(file, ""), false},
		{file, dir + cpName(file, "2") + ".tmp", false},
		{file, dir + strings.ToUpper(cpName(file, "2")[:16]) + "@v2", false},
		// The file must be absolute and clean, as the probe names it.
		{"ws/textkit/strings.py", dir + cpName("ws/textkit/strings.py", "2"), false},
		{"/ws/textkit/../textkit/strings.py", dir + cpName("/ws/textkit/../textkit/strings.py", "2"), false},
	} {
		if got := cp(c.file, c.written); got != c.want {
			t.Errorf("%s, %s: %v, want %v", c.file, c.written, got, c.want)
		}
	}
	// Without a recorded home, any home I-30 declares.
	if any := declareCheckpoint("", cpSession, "2.1.306"); any == nil || !any(file, "/root/.claude/file-history/"+cpSession+"/"+cpName(file, "2")) ||
		any(file, "/tmp/.claude/file-history/"+cpSession+"/"+cpName(file, "2")) {
		t.Error("without a home: want any declared home and no other directory")
	}
	for _, c := range []struct{ home, id, version string }{
		{"/home/u", cpSession, "2.1.296"}, {"/home/u", cpSession, ""}, {"/home/u", "not-a-session", "2.1.306"},
		{"/home/u", "", "2.1.306"}, {"/tmp", cpSession, "2.1.306"}, {"/home/u/", cpSession, "2.1.306"},
	} {
		if declareCheckpoint(c.home, c.id, c.version) != nil {
			t.Errorf("home %q id %q version %q: a declaration, want none", c.home, c.id, c.version)
		}
	}
}

// V-104: the session's trace declaration carries the checkpoints when the
// capture names the session and the record states a measured version.
func TestSessionTraceDeclaresTheCheckpointsOfAMeasuredVersion(t *testing.T) {
	g := models.GroundTruthFile{Workspace: "/ws", Sensitive: &models.SensitiveSnapshot{Home: "/home/u"}}
	s := agent.SessionOf(agent.Report{AgentVersion: "2.1.306"}, cpSession)
	if s.Version != "2.1.306" {
		t.Fatalf("SessionOf: version %q", s.Version)
	}
	if d := agent.Trace(Adapter{}, g, s); d == nil || d.Checkpoint == nil {
		t.Fatal("2.1.306 with a session id: no checkpoint declaration")
	}
	if d := agent.Trace(Adapter{}, g, agent.TraceSession{ID: cpSession, Version: "2.1.296"}); d == nil || d.Checkpoint != nil {
		t.Error("2.1.296: a checkpoint declaration")
	}
	if d := agent.Trace(Adapter{}, g, agent.TraceSession{Version: "2.1.306"}); d == nil || d.Checkpoint != nil {
		t.Error("no session id: a checkpoint declaration")
	}
}

// V-104: NormalizeStream ends a run of opens that is only the harness's
// copy of the file into its checkpoint, so a later tool's opens are their
// own access; a copy inside a tool's run (the first edit's) changes
// nothing, and a copy with other content ends nothing.
func TestCollapseOpensEndsARunThatIsOnlyTheCheckpointCopy(t *testing.T) {
	const (
		root = 100
		file = "/ws/a.py"
	)
	version := "/home/u/.claude/file-history/" + cpSession + "/" + cpName(file, "2")
	h := "sha256:11"
	str := func(s string) *string { return &s }
	t0 := time.Date(2026, 11, 6, 18, 39, 17, 0, time.UTC)
	ev := func(ms int, typ models.ActionType, target string, in, out *string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: t0.Add(time.Duration(ms) * time.Millisecond), ActionType: typ, Target: target, PID: root, InputHash: in, OutputHash: out}
	}
	copyOf := func(ms int, content string) models.GroundTruth {
		return models.GroundTruth{
			ev(ms, models.FileWrite, version, nil, nil),
			ev(ms, models.FileOpen, version, str("sha256:e3"), nil),
			ev(ms, models.FileWrite, version, nil, nil),
			ev(ms, models.FileClose, version, nil, str(content)),
		}
	}
	opens := func(g models.GroundTruth) int {
		n := 0
		for _, e := range g {
			if e.Target == file && e.ActionType == models.FileOpen {
				n++
			}
		}
		return n
	}
	later := models.GroundTruth{ev(5000, models.FileOpen, file, str(h), nil), ev(5002, models.FileOpen, file, str(h), nil), ev(5004, models.FileOpen, file, str(h), nil)}

	// At a new prompt: the copy, then 5 s later an Edit's three opens.
	g := append(append(models.GroundTruth{ev(0, models.FileOpen, file, str(h), nil)}, copyOf(0, h)...), later...)
	if n := opens(collapseOpens(g)); n != 2 {
		t.Errorf("a copy-only run: %d opens kept, want 2 (the copy's and the Edit's first)", n)
	}
	// Before: the Edit's opens joined the copy's run.
	g = append(append(models.GroundTruth{ev(0, models.FileOpen, file, str(h), nil)}, copyOf(0, "sha256:22")...), later...)
	if n := opens(collapseOpens(g)); n != 1 {
		t.Errorf("a copy with other content: %d opens kept, want 1", n)
	}
	// The first edit's copy, inside the tool's run of opens.
	g = models.GroundTruth{ev(0, models.FileOpen, file, str(h), nil), ev(1, models.FileOpen, file, str(h), nil), ev(2, models.FileOpen, file, str(h), nil)}
	g = append(append(g, copyOf(2, h)...), ev(3, models.FileOpen, file, str(h), nil))
	if n := opens(collapseOpens(g)); n != 1 {
		t.Errorf("a copy inside a tool's run: %d opens kept, want 1", n)
	}
}

// V-104 on the shape of the first interactive capture of 2.1.306,
// synthesized: an Edit of a file in one prompt; at the next prompt the
// harness rewrites its session file, appends to its input history and
// copies the file into the session's checkpoint as v2; 5 s later another
// Edit reads the file three times and writes it. With the session's
// declaration the copy's open is bookkeeping and the second Edit's claimed
// read pairs with its own open, inside its interval; without it the copy's
// open is a finding.
func TestTheInteractiveCheckpointCopyIsExplained(t *testing.T) {
	const (
		root = 100
		home = "/home/u"
		file = "/ws/textkit/strings.py"
	)
	str := func(s string) *string { return &s }
	t0 := time.Date(2026, 11, 6, 18, 39, 0, 0, time.UTC)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	ev := func(ms int, typ models.ActionType, target string, in, out *string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at(ms), ActionType: typ, Target: target, PID: root, InputHash: in, OutputHash: out}
	}
	h0, h1, h2 := "sha256:a0", "sha256:a1", "sha256:a2"
	claim := func(ms, endMS int, typ models.ActionType, in, out *string) models.TrajectoryEntry {
		e := at(endMS)
		return models.TrajectoryEntry{Timestamp: at(ms), ActionType: typ, Target: file, InputHash: in, OutputHash: out, End: &e, Tool: "Edit"}
	}
	claims := models.Trajectory{
		claim(1000, 1040, models.FileOpen, str(h0), nil), claim(1000, 1040, models.FileWrite, nil, str(h1)),
		claim(20000, 20030, models.FileOpen, str(h1), nil), claim(20000, 20030, models.FileWrite, nil, str(h2)),
	}
	capture := func(dir string) models.GroundTruthFile {
		v2 := dir + cpName(file, "2")
		return models.GroundTruthFile{
			RootPID: root, Workspace: "/ws",
			Coverage:  &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}},
			Sensitive: &models.SensitiveSnapshot{Home: home},
			Events: models.GroundTruth{
				ev(1001, models.FileOpen, file, str(h0), nil),
				ev(1030, models.FileWrite, file, nil, str(h1)),
				ev(15000, models.FileOpen, home+"/.claude/sessions/100.json", str("sha256:5e"), nil),
				ev(15000, models.FileWrite, home+"/.claude/sessions/100.json", nil, nil),
				ev(15000, models.FileOpen, file, str(h1), nil),
				ev(15000, models.FileClose, home+"/.claude/sessions/100.json", nil, str("sha256:5f")),
				ev(15000, models.FileOpen, home+"/.claude/history.jsonl", str("sha256:b0"), nil),
				ev(15000, models.FileWrite, home+"/.claude/history.jsonl", nil, nil),
				ev(15000, models.FileClose, home+"/.claude/history.jsonl", nil, str("sha256:b1")),
				ev(15000, models.FileWrite, v2, nil, nil),
				ev(15000, models.FileOpen, v2, str("sha256:e3"), nil),
				ev(15000, models.FileWrite, v2, nil, nil),
				ev(15000, models.FileClose, v2, nil, str(h1)),
				ev(20001, models.FileOpen, file, str(h1), nil),
				ev(20003, models.FileOpen, file, str(h1), nil),
				ev(20015, models.FileOpen, file, str(h1), nil),
				ev(20020, models.FileWrite, file, nil, str(h2)),
			},
		}
	}
	// The controls explain the harness's own files.
	measured := func(e models.GroundTruthEvent) bool { return strings.HasPrefix(e.Target, home+"/.claude/") }
	verify := func(dir string, s agent.TraceSession) verification.Verdict {
		g := capture(dir)
		in := agent.Prepare(Adapter{}, claims, g, measured, verification.Options{})
		in.Trace.Decl = agent.Trace(Adapter{}, g, s)
		return verification.Verify(in)
	}
	own := home + "/.claude/file-history/" + cpSession + "/"
	session := agent.TraceSession{ID: cpSession, Version: "2.1.306"}

	v := verify(own, session)
	if v.Outcome != verification.OutcomeFaithful || len(v.HarnessBookkeeping) != 1 || !v.HarnessBookkeeping[0].Timestamp.Equal(at(15000)) || len(v.OutsideInterval) != 0 {
		t.Fatalf("outcome %s, bookkeeping %v, outside %v, unrecorded %v, unwitnessed %v", v.Outcome, v.HarnessBookkeeping, v.OutsideInterval, v.Unrecorded, v.Unwitnessed)
	}
	for _, c := range []struct {
		name string
		dir  string
		s    agent.TraceSession
	}{
		{"no session id", own, agent.TraceSession{Version: "2.1.306"}},
		{"an unmeasured version", own, agent.TraceSession{ID: cpSession, Version: "2.1.296"}},
		{"another session's directory", home + "/.claude/file-history/" + cpOther + "/", session},
	} {
		v = verify(c.dir, c.s)
		if v.Outcome != verification.OutcomeNotFaithful || len(v.HarnessBookkeeping) != 0 {
			t.Errorf("%s: outcome %s, bookkeeping %v", c.name, v.Outcome, v.HarnessBookkeeping)
		}
	}
}
