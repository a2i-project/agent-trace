package verification

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

const agentPID = 100

var t0 = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

func fork(ms int, pid, ppid uint32) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: at(ms), ActionType: models.ProcessFork, Target: "x", PID: pid, PPID: ppid}
}

func execEv(ms int, pid, ppid uint32, target string) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: at(ms), ActionType: models.ProcessExec, Target: target, PID: pid, PPID: ppid}
}

func fsEv(ms int, pid uint32, path string) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: at(ms), ActionType: models.FileWrite, Target: path, PID: pid}
}

func TestForest_LevelsAndCommands(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID), execEv(2, 200, agentPID, "/bin/sh -c x"), // level 1: a command
		fork(3, 201, 200), execEv(4, 201, 200, "/usr/bin/cat f"), // level 2
		fork(5, 202, 201),                                   // level 3, never execs
		fork(6, 203, 202), execEv(7, 203, 202, "/bin/deep"), // level 4
		fork(8, 300, agentPID), execEv(9, 300, agentPID, "/bin/ls"), // a second command
	}
	f := BuildForest(g, agentPID)

	wantLevel := map[uint32]int{200: 1, 201: 2, 202: 3, 203: 4, 300: 1}
	for pid, want := range wantLevel {
		p := f.Resolve(pid, at(10))
		if p == nil || p.Level != want {
			t.Fatalf("pid %d: process %+v, want level %d", pid, p, want)
		}
	}
	// A deep descendant attributes to the level-1 command it grew from.
	a := f.Attribute(fsEv(20, 203, "/w/out"))
	if a.Zone != ZoneSubtree || a.Level != 4 || a.Command == nil || a.Command.PID != 200 {
		t.Errorf("deep descendant attribution = %+v, want subtree level 4 under command 200", a)
	}
	// A process that never exec'd is placed by its fork record alone.
	if a := f.Attribute(fsEv(20, 202, "/w/sub")); a.Zone != ZoneSubtree || a.Command.PID != 200 {
		t.Errorf("fork-only process attribution = %+v", a)
	}
	cmds := f.Commands()
	if len(cmds) != 2 || cmds[0].PID != 200 || cmds[1].PID != 300 {
		t.Errorf("Commands() = %v, want 200 then 300 in creation order", cmds)
	}
	if cmds[0].Exec == nil || cmds[0].Exec.Target != "/bin/sh -c x" {
		t.Errorf("command 200 lost its exec record: %+v", cmds[0].Exec)
	}
}

func TestForest_ZonesOfNonSubtreeEvents(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID),
		fork(2, 900, 800), // 800 was never seen: someone else's process
	}
	f := BuildForest(g, agentPID)
	tests := []struct {
		name string
		e    models.GroundTruthEvent
		want Zone
	}{
		{"the agent itself", fsEv(5, agentPID, "/w/a"), ZoneAgent},
		{"a descendant", fsEv(5, 200, "/w/a"), ZoneSubtree},
		{"a pid never seen", fsEv(5, 777, "/w/a"), ZoneOutside},
		{"a pid whose parent was never seen", fsEv(5, 900, "/w/a"), ZoneOutside},
		{"no pid recorded", fsEv(5, 0, "/w/a"), ZoneUnknown},
	}
	for _, tc := range tests {
		if got := f.Attribute(tc.e); got.Zone != tc.want {
			t.Errorf("%s: zone = %s, want %s", tc.name, got.Zone, tc.want)
		}
	}
	if o := f.Orphans(); len(o) != 1 || o[0].PID != 900 {
		t.Errorf("Orphans() = %v, want pid 900 only", o)
	}
}

// A process that outlives its parent keeps the command that created it: the
// edge is the one recorded at fork, not whatever the kernel says later.
func TestForest_OutlivesParentAndReparenting(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID), execEv(2, 200, agentPID, "/bin/sh -c bg"),
		fork(3, 201, 200), execEv(4, 201, 200, "/bin/server"),
		{Timestamp: at(5), ActionType: models.ProcessExit, Target: "/bin/sh -c bg", PID: 200, PPID: agentPID},
		// The server is now reparented to init: its later exec-time ppid
		// would say 1, but the fork edge says 200.
		execEv(6, 201, 1, "/bin/server --reexec"),
	}
	f := BuildForest(g, agentPID)
	a := f.Attribute(fsEv(10_000, 201, "/w/log")) // ten seconds after the parent exited
	if a.Zone != ZoneSubtree || a.Command == nil || a.Command.PID != 200 || a.Level != 2 {
		t.Errorf("orphaned server attribution = %+v, want level 2 under command 200", a)
	}
}

// After a pid's process exits the number can be reused. Time picks between
// the incarnations, and an event goes to the one alive when it happened.
func TestForest_PIDReuse(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID),  // command A
		fork(2, 500, 200),       // incarnation 1 of pid 500, under A
		fork(10, 300, agentPID), // command B
		fork(11, 500, 300),      // incarnation 2 of pid 500, under B
		fork(12, 501, 900),      // an unrelated process whose parent is unknown
		fork(20, 500, 501),      // incarnation 3 of pid 500, outside the tree
	}
	f := BuildForest(g, agentPID)
	tests := []struct {
		ms          int
		wantZone    Zone
		wantCommand uint32
	}{
		{5, ZoneSubtree, 200},
		{15, ZoneSubtree, 300},
		{25, ZoneOutside, 0},
	}
	for _, tc := range tests {
		a := f.Attribute(fsEv(tc.ms, 500, "/w/x"))
		if a.Zone != tc.wantZone {
			t.Errorf("t=%dms: zone = %s, want %s", tc.ms, a.Zone, tc.wantZone)
			continue
		}
		if tc.wantZone == ZoneSubtree && a.Command.PID != tc.wantCommand {
			t.Errorf("t=%dms: command = %d, want %d", tc.ms, a.Command.PID, tc.wantCommand)
		}
	}
}

// An event stamped before the first record of its pid (probe clock skew) is
// kept with the earliest incarnation instead of being dropped.
func TestForest_EventBeforeItsForkRecordIsNotDropped(t *testing.T) {
	f := BuildForest(models.GroundTruth{fork(10, 200, agentPID)}, agentPID)
	if a := f.Attribute(fsEv(5, 200, "/w/x")); a.Zone != ZoneSubtree {
		t.Errorf("zone = %s, want subtree", a.Zone)
	}
}

// Ground truth recorded before fork records existed has only exec records.
// The tree is then built from their ppid, so the old files still verify.
func TestForest_LegacyExecOnlyGroundTruth(t *testing.T) {
	g := models.GroundTruth{
		execEv(1, 200, agentPID, "/bin/sh -c x"),
		execEv(2, 201, 200, "/bin/ls"),
	}
	f := BuildForest(g, agentPID)
	if a := f.Attribute(fsEv(5, 201, "/w/x")); a.Zone != ZoneSubtree || a.Level != 2 || a.Command.PID != 200 {
		t.Errorf("attribution = %+v, want level 2 under command 200", a)
	}
}

// Ground truth with no pids at all, as written before step 1, cannot be
// placed. Every event must come out unknown, not silently outside or agent.
func TestForest_GroundTruthWithoutPIDsIsUnknown(t *testing.T) {
	f := BuildForest(models.GroundTruth{{Timestamp: at(1), ActionType: models.ProcessExec, Target: "/bin/ls"}}, agentPID)
	if a := f.Attribute(models.GroundTruthEvent{Timestamp: at(2), ActionType: models.FileOpen, Target: "/w/x"}); a.Zone != ZoneUnknown {
		t.Errorf("zone = %s, want unknown", a.Zone)
	}
	if len(f.Commands()) != 0 {
		t.Error("a forest without pids must have no commands")
	}
}

// Construction must not depend on the order events arrive in, which differs
// between probes.
func TestForest_InputOrderDoesNotMatter(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID), fork(2, 201, 200), fork(3, 202, 201),
	}
	reversed := models.GroundTruth{g[2], g[1], g[0]}
	for name, in := range map[string]models.GroundTruth{"forward": g, "reversed": reversed} {
		f := BuildForest(in, agentPID)
		if a := f.Attribute(fsEv(10, 202, "/w/x")); a.Level != 3 || a.Command.PID != 200 {
			t.Errorf("%s: attribution = %+v, want level 3 under 200", name, a)
		}
	}
}

// A cycle in the records (equal stamps, corrupt data) must terminate and place
// both processes outside the tree.
func TestForest_CorruptCycleTerminates(t *testing.T) {
	g := models.GroundTruth{fork(1, 400, 401), fork(1, 401, 400)}
	f := BuildForest(g, agentPID)
	if a := f.Attribute(fsEv(5, 400, "/w/x")); a.Zone != ZoneOutside {
		t.Errorf("zone = %s, want outside", a.Zone)
	}
}
