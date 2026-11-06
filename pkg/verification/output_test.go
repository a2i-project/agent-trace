package verification

import (
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// boundEv is an event of process pid read at ms whose NotBefore is nb.
func boundEv(ms, nb int, pid uint32, typ models.ActionType, target string) models.GroundTruthEvent {
	e := models.GroundTruthEvent{Timestamp: at(ms), ActionType: typ, Target: target, PID: pid}
	if nb >= 0 {
		t := at(nb)
		e.NotBefore = &t
	}
	return e
}

func msPtr(ms int) *time.Time {
	t := at(ms)
	return &t
}

// outputCase is a background command whose output the harness keeps in
// /tmp/h/tasks/b1.output: the command (pid 200) writes it until 2995, the
// harness reports the end at 3000, and reads, writes and closes it itself.
// The controls ran no background command, so no baseline explains any of it.
type outputCase struct {
	nb       func(int) int // the NotBefore of an event read at ms, -1 for none
	stepped  bool
	named    bool
	reported bool
}

const outFile = "/tmp/h/tasks/b1.output"

func (c outputCase) ground(extra ...models.GroundTruthEvent) models.GroundTruth {
	root := func(ms int, typ models.ActionType) models.GroundTruthEvent {
		return boundEv(ms, c.nb(ms), agentPID, typ, outFile)
	}
	g := models.GroundTruth{
		fork(5, 200, agentPID), execEv(6, 200, agentPID, "sleep 3"),
		root(7, models.FileWrite), root(7, models.FileOpen), // the harness creates the file
		root(1000, models.FileOpen), root(2000, models.FileOpen), // and polls it
		boundEv(2990, -1, 200, models.FileWrite, outFile), boundEv(2995, -1, 200, models.FileClose, outFile),
		root(3001, models.FileOpen),                                                             // reads it once the command ended
		root(3005, models.FileOpen), root(3006, models.FileWrite), root(3006, models.FileClose), // writes the exit to it
	}
	return append(g, extra...)
}

func (c outputCase) claims(extra ...models.TrajectoryEntry) models.Trajectory {
	cmd := claimAt(4, models.ProcessExec, "sleep 3")
	cmd.End = msPtr(40)
	if c.named {
		cmd.OutputName = "b1.output"
	}
	if c.reported {
		cmd.OutputDone = msPtr(3000)
	}
	return append(models.Trajectory{cmd}, extra...)
}

func (c outputCase) verify(claims models.Trajectory, g models.GroundTruth) Verdict {
	cov := completeCov()
	if c.stepped {
		fs := cov.Probes["fs"]
		fs.ClockStepped = true
		cov.Probes["fs"] = fs
	}
	return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: cov, Options: Options{
		HarnessOwned:     func(p string) bool { return strings.HasPrefix(p, "/tmp/h/") },
		BackgroundOutput: func(p string) bool { return strings.HasSuffix(p, ".output") },
	}})
}

// The probe found the queue empty 1 ms before it read each event.
func tight(ms int) int { return ms - 1 }

// The harness's own events on the output file of a claimed background
// command are explained without a baseline, its final write after the
// reported end included, and an open whose earliest moment is after the end
// is the agent's (V-101).
func TestVerify_TheHarnessOwnEventsOnAClaimedCallsOutputAreExplained(t *testing.T) {
	c := outputCase{nb: tight, named: true, reported: true}
	if v := c.verify(c.claims(), c.ground()); v.Outcome != OutcomeFaithful || len(v.UnexplainedHarness) != 0 {
		t.Fatalf("the harness's events alone: %s, unexplained harness %v, reasons %v", v.Outcome, v.UnexplainedHarness, v.Reasons)
	}
	read := boundEv(15000, 14000, agentPID, models.FileOpen, outFile)
	claimed := c.verify(c.claims(claimAt(14990, models.FileOpen, outFile)), c.ground(read))
	if claimed.Outcome != OutcomeFaithful || len(claimed.Corroborated) != 2 {
		t.Errorf("a claimed read after the end: %s, %d corroborated, unwitnessed %v", claimed.Outcome, len(claimed.Corroborated), claimed.Unwitnessed)
	}
	omitted := c.verify(c.claims(), c.ground(read))
	if omitted.Outcome != OutcomeNotFaithful || len(omitted.Unrecorded) != 1 || !omitted.Unrecorded[0].Timestamp.Equal(read.Timestamp) {
		t.Errorf("an unclaimed read after the end: %s, unrecorded %v", omitted.Outcome, omitted.Unrecorded)
	}
}

// What decides is the event's earliest moment, not when the probe read it:
// an open the probe read 500 ms after the end, from a queue last found empty
// before it, may be the harness's read and is explained; one whose earliest
// moment is a millisecond after the end is the agent's, however close.
func TestVerify_AnOutputOpenIsJudgedByItsEarliestMoment(t *testing.T) {
	c := outputCase{nb: tight, named: true, reported: true}
	late := boundEv(3500, 2999, agentPID, models.FileOpen, outFile)
	if v := c.verify(c.claims(), c.ground(late)); v.Outcome != OutcomeFaithful {
		t.Errorf("an open read late that may precede the end: %s, unrecorded %v", v.Outcome, v.Unrecorded)
	}
	after := boundEv(3010, 3001, agentPID, models.FileOpen, outFile)
	if v := c.verify(c.claims(), c.ground(after)); v.Outcome != OutcomeNotFaithful || len(v.Unrecorded) != 1 {
		t.Errorf("an open that began after the end: %s, unrecorded %v", v.Outcome, v.Unrecorded)
	}
}

// Without the bound the rule does not judge an open, and V-56 applies as
// before: the harness's polls stay unexplained without a baseline, and an
// open more than a second after the last write is the agent's. The same
// holds when the wall clock stepped, or the call's end is not reported. The
// harness's writes are explained in every case, since they need no time.
func TestVerify_WithoutABoundOutputOpensAreLeftToTheEarlierRules(t *testing.T) {
	read := boundEv(15000, 14000, agentPID, models.FileOpen, outFile)
	for name, c := range map[string]outputCase{
		"no bound":     {nb: func(int) int { return -1 }, named: true, reported: true},
		"clock step":   {nb: tight, stepped: true, named: true, reported: true},
		"end unstated": {nb: tight, named: true},
	} {
		v := c.verify(c.claims(), c.ground(read))
		if v.Outcome == OutcomeFaithful {
			t.Errorf("%s: FAITHFUL", name)
		}
		if len(v.Unrecorded) != 1 || !v.Unrecorded[0].Timestamp.Equal(read.Timestamp) {
			t.Errorf("%s: unrecorded %v, want the read, by V-56", name, v.Unrecorded)
		}
		for _, e := range v.UnexplainedHarness {
			if e.ActionType != models.FileOpen {
				t.Errorf("%s: the harness's %s at %v is unexplained", name, e.ActionType, e.Timestamp)
			}
		}
	}
}

// A file no claim names, and no claim's interval holds, is not linked: its
// events are read as before V-101, all eight of the harness's unexplained
// harness activity here.
func TestVerify_AnUnlinkedOutputFileIsNotExplained(t *testing.T) {
	c := outputCase{nb: tight}
	claims := c.claims()
	claims[0].End = msPtr(5)
	claims[0].OutputDone = msPtr(5)
	v := c.verify(claims, c.ground())
	// The call's interval here also misses its own exec, so the run is not
	// FAITHFUL on that account too; what matters is the harness's events.
	if v.Outcome == OutcomeFaithful || len(v.UnexplainedHarness) != 8 {
		t.Errorf("an unlinked output file: %s, unexplained harness %v, unrecorded %v, unwitnessed %v, mismatched %v, outside %v, subtrees %d", v.Outcome, v.UnexplainedHarness, v.Unrecorded, v.Unwitnessed, v.Mismatched, v.OutsideInterval, len(v.Coverage.UnexplainedSubtrees))
	}
}

// A foreground call's file is unnamed: it is linked by the call's interval,
// which holds the earliest moment of its first event, and judged against
// the call's result.
func TestVerify_AForegroundCallsOutputIsLinkedByItsInterval(t *testing.T) {
	c := outputCase{nb: tight}
	claims := c.claims()
	claims[0].End = msPtr(3002)
	claims[0].OutputDone = msPtr(3002)
	if v := c.verify(claims, c.ground()); v.Outcome != OutcomeFaithful {
		t.Errorf("the harness's events on a foreground call's output: %s, unexplained harness %v, unrecorded %v", v.Outcome, v.UnexplainedHarness, v.Unrecorded)
	}
	read := boundEv(15000, 14000, agentPID, models.FileOpen, outFile)
	if v := c.verify(claims, c.ground(read)); v.Outcome != OutcomeNotFaithful || len(v.Unrecorded) != 1 {
		t.Errorf("an unclaimed read after the result: %s, unrecorded %v", v.Outcome, v.Unrecorded)
	}
}

// The rule takes only the agent's own process: a write by another process
// on the file is not the harness's.
func TestVerify_TheOutputRuleTakesOnlyTheAgentsProcess(t *testing.T) {
	c := outputCase{nb: tight, named: true, reported: true}
	stranger := boundEv(5000, 4999, 300, models.FileWrite, outFile)
	rule := harnessOutputs(Input{Claims: c.claims(), Ground: c.ground(stranger), RootPID: agentPID, Coverage: completeCov(), Options: Options{BackgroundOutput: func(p string) bool { return strings.HasSuffix(p, ".output") }}})
	if decided, _ := rule.decided(stranger); decided {
		t.Error("another process's write was decided by the rule")
	}
	if decided, agents := rule.decided(c.ground()[11]); !decided || agents {
		t.Error("the harness's final close was not taken as the harness's")
	}
}
