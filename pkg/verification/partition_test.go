package verification

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func exitEv(ms int, pid, ppid uint32, target string) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: at(ms), ActionType: models.ProcessExit, Target: target, PID: pid, PPID: ppid}
}

func TestPartition_SortsEventsIntoTheirParts(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID), execEv(2, 200, agentPID, "/bin/sh -c x"), // command 1
		fork(3, 201, 200), execEv(4, 201, 200, "/usr/bin/cat f"), // descendant
		fsEv(5, 201, "/w/by-descendant"),
		fsEv(6, 200, "/w/by-command-itself"),
		fsEv(7, agentPID, "/w/by-agent"),
		exitEv(8, 201, 200, "/usr/bin/cat f"),
		exitEv(9, 200, agentPID, "/bin/sh -c x"),
		fsEv(10, 777, "/w/by-stranger"),
		fsEv(11, 0, "/w/by-nobody"),
		{Timestamp: at(12), ActionType: models.NetListen, Target: "0.0.0.0:80", PID: 201},
		fork(13, 300, agentPID), execEv(14, 300, agentPID, "/bin/ls"), // command 2, never claimed
	}
	f := BuildForest(g, agentPID)
	p := f.Partition(g)

	// The aligned sequence: the agent's own event and each command's own
	// exec and exit, nothing from inside a subtree.
	want := []string{"/bin/sh -c x", "/w/by-agent", "/bin/sh -c x", "/bin/ls"} // exec, agent write, exit, second command
	if len(p.Observed) != len(want) {
		t.Fatalf("Observed = %v, want targets %v", p.Observed, want)
	}
	for i, w := range want {
		if p.Observed[i].Target != w {
			t.Errorf("Observed[%d] = %q, want %q", i, p.Observed[i].Target, w)
		}
	}

	if len(p.Commands) != 2 {
		t.Fatalf("Commands = %d, want 2", len(p.Commands))
	}
	c1 := p.Commands[0]
	if c1.Exec == nil || c1.Exec.Target != "/bin/sh -c x" || c1.Exit == nil {
		t.Errorf("command 1 exec/exit = %v / %v", c1.Exec, c1.Exit)
	}
	// Everything beneath the command is content: the descendant's exec and
	// exit, and every file event, including the command's own.
	var content []string
	for _, e := range c1.Content {
		content = append(content, e.Target)
	}
	wantContent := []string{"/usr/bin/cat f", "/w/by-descendant", "/w/by-command-itself", "/usr/bin/cat f"}
	if len(content) != len(wantContent) {
		t.Fatalf("command 1 content = %v, want %v", content, wantContent)
	}
	for i := range wantContent {
		if content[i] != wantContent[i] {
			t.Errorf("content[%d] = %q, want %q", i, content[i], wantContent[i])
		}
	}
	if p.Commands[1].Exec == nil || len(p.Commands[1].Content) != 0 {
		t.Errorf("command 2 = %+v", p.Commands[1])
	}

	if len(p.Outside) != 1 || p.Outside[0].Target != "/w/by-stranger" {
		t.Errorf("Outside = %v", p.Outside)
	}
	if len(p.Unknown) != 1 || p.Unknown[0].Target != "/w/by-nobody" {
		t.Errorf("Unknown = %v", p.Unknown)
	}
	// The listener is capability evidence with its place in the tree, and the
	// fork records appear nowhere.
	if len(p.Capability) != 1 || p.Capability[0].Zone != ZoneSubtree || p.Capability[0].Command.PID != 200 {
		t.Errorf("Capability = %+v", p.Capability)
	}
}

// A level-1 process that execs twice (a shell that execs its last command, as
// dash does) has one command exec, the first. The second is content of the
// command, or the claim would see two commands where the agent ran one.
func TestPartition_OnlyTheFirstExecIsTheCommand(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID),
		execEv(2, 200, agentPID, "/bin/sh -c a; b"),
		execEv(3, 200, agentPID, "/bin/b"), // the shell exec'd its last command
	}
	p := BuildForest(g, agentPID).Partition(g)
	if len(p.Observed) != 1 || p.Observed[0].Target != "/bin/sh -c a; b" {
		t.Errorf("Observed = %v, want only the first exec", p.Observed)
	}
	if len(p.Commands[0].Content) != 1 || p.Commands[0].Content[0].Target != "/bin/b" {
		t.Errorf("content = %v, want the second exec", p.Commands[0].Content)
	}
}

// A fork with no exec is a command with no claimable exec: it is kept as a
// command so coverage can see the subtree, but it contributes nothing to the
// aligned sequence.
func TestPartition_ForkWithoutExecIsACommandWithNoExec(t *testing.T) {
	g := models.GroundTruth{fork(1, 200, agentPID), fsEv(2, 200, "/w/x")}
	p := BuildForest(g, agentPID).Partition(g)
	if len(p.Commands) != 1 || p.Commands[0].Exec != nil || len(p.Commands[0].Content) != 1 {
		t.Errorf("Commands = %+v", p.Commands)
	}
	if len(p.Observed) != 0 {
		t.Errorf("Observed = %v, want none", p.Observed)
	}
}

// Probes deliver in different orders, so Observed is sorted by time itself.
func TestPartition_ObservedIsInTimeOrder(t *testing.T) {
	g := models.GroundTruth{fsEv(30, agentPID, "/w/c"), fsEv(10, agentPID, "/w/a"), fsEv(20, agentPID, "/w/b")}
	p := BuildForest(g, agentPID).Partition(g)
	for i, w := range []string{"/w/a", "/w/b", "/w/c"} {
		if p.Observed[i].Target != w {
			t.Errorf("Observed[%d] = %q, want %q", i, p.Observed[i].Target, w)
		}
	}
}
