package agent

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// launching is a fake adapter whose harness is the root's child execing
// /opt/harness.
type launching struct{ fake }

func (launching) HarnessProcess(g models.GroundTruthFile) uint32 {
	for _, e := range g.Events {
		if e.ActionType == models.ProcessExec && e.Target == "/opt/harness" && e.PPID == g.RootPID {
			return e.PID
		}
	}
	return 0
}

// launched is a capture of a launcher (pid 10) that reads its script and
// starts the harness (pid 11), which writes a file and runs one command
// (pid 12).
func launched() models.GroundTruthFile {
	t0 := time.Unix(1000, 0)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	return models.GroundTruthFile{RootPID: 10, Events: models.GroundTruth{
		{Timestamp: at(0), ActionType: models.FileOpen, Target: "/opt/launcher.js", PID: 10},
		{Timestamp: at(1), ActionType: models.NetUnixConnect, Target: "unix:/run/nscd/socket", PID: 10},
		{Timestamp: at(2), ActionType: models.ProcessFork, Target: "11", PID: 11, PPID: 10},
		{Timestamp: at(3), ActionType: models.ProcessExec, Target: "/opt/harness", PID: 11, PPID: 10},
		{Timestamp: at(4), ActionType: models.FileWrite, Target: "/ws/a.txt", PID: 11},
		{Timestamp: at(5), ActionType: models.ProcessFork, Target: "12", PID: 12, PPID: 11},
		{Timestamp: at(6), ActionType: models.ProcessExec, Target: "echo hi", PID: 12, PPID: 11},
		{Timestamp: at(7), ActionType: models.ProcessExit, Target: "echo hi", PID: 12, PPID: 11},
		{Timestamp: at(8), ActionType: models.ProcessExit, Target: "/opt/harness", PID: 11, PPID: 10},
	}}
}

func TestRootedRootsTheCaptureAtTheHarness(t *testing.T) {
	g := Rooted(launching{}, launched())
	if g.RootPID != 11 {
		t.Fatalf("root %d, want the harness 11", g.RootPID)
	}
	for _, e := range g.Events {
		if e.PID == 11 && e.ActionType != models.FileWrite {
			t.Errorf("the launch record %+v stayed", e)
		}
	}
	if len(g.Events) != 6 {
		t.Errorf("%d events, want the launcher's two, the write and the command's three", len(g.Events))
	}
	// The harness's write is the agent's own (level 0), the command level 1.
	f := verification.BuildForest(g.Events, g.RootPID)
	if a := f.Attribute(g.Events[2]); a.Zone != verification.ZoneAgent {
		t.Errorf("the harness's write is %v, want the agent's", a.Zone)
	}
	if cmds := f.Commands(); len(cmds) != 1 || cmds[0].PID != 12 {
		t.Errorf("commands %v, want the harness's one command", cmds)
	}
	// The input is not changed.
	if raw := launched(); raw.RootPID != 10 || len(raw.Events) != 9 {
		t.Error("Rooted changed its input")
	}
}

// A root that does more than launch, a second child, or an adapter that
// names no harness leaves the capture as it is: the harness stays a command
// and nothing of the root's moves out of the tree.
func TestRootedFailsClosed(t *testing.T) {
	cases := map[string]func(*models.GroundTruthFile){
		"the root writes": func(g *models.GroundTruthFile) {
			g.Events = append(g.Events, models.GroundTruthEvent{Timestamp: time.Unix(1001, 0), ActionType: models.FileWrite, Target: "/tmp/x", PID: 10})
		},
		"the root connects": func(g *models.GroundTruthFile) {
			g.Events = append(g.Events, models.GroundTruthEvent{Timestamp: time.Unix(1001, 0), ActionType: models.NetConnect, Target: "example.com", PID: 10})
		},
		"the root starts a second child": func(g *models.GroundTruthFile) {
			g.Events = append(g.Events, models.GroundTruthEvent{Timestamp: time.Unix(1001, 0), ActionType: models.ProcessFork, Target: "13", PID: 13, PPID: 10})
		},
		"no harness": func(g *models.GroundTruthFile) { g.Events[3].Target = "/opt/other" },
	}
	for name, change := range cases {
		g := launched()
		change(&g)
		if r := Rooted(launching{}, g); r.RootPID != 10 || len(r.Events) != len(g.Events) {
			t.Errorf("%s: rooted at %d with %d events, want the capture as it is", name, r.RootPID, len(r.Events))
		}
	}
	if r := Rooted(fake{}, launched()); r.RootPID != 10 {
		t.Error("an adapter without a launcher rerooted the capture")
	}
}

// Prepare and Capture both root the capture, so a baseline built from
// launched controls explains the harness's own events in a launched run.
func TestPrepareAndCaptureRootAtTheHarness(t *testing.T) {
	a := launching{fake{name: "l", model: ProcessModel{ExitsClaimed: false}}}
	b, err := Capture(a, "1", []models.GroundTruthFile{launched()}, time.Now(), CaptureOptions{Exclude: []string{"echo hi"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range b.Rules {
		if r.Target == "/opt/harness" {
			t.Errorf("the launch is a rule: %+v", r)
		}
	}
	claims := models.Trajectory{{Timestamp: time.Unix(1000, 0), ActionType: models.ProcessExec, Target: "echo hi"}}
	in := PrepareWithBaseline(a, claims, launched(), &b, verification.Options{})
	if in.RootPID != 11 {
		t.Fatalf("Prepare rooted at %d, want 11", in.RootPID)
	}
	if v := verification.Verify(in); len(v.Corroborated) != 1 || v.Findings() != 0 {
		t.Errorf("corroborated %d, findings %d; want the command corroborated and no finding", len(v.Corroborated), v.Findings())
	}
}
