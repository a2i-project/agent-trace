package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// The session's declared trace in these tests: the main file and a
// directory of subagent files beside it (I-74, V-59).
const (
	traceMain = "/home/u/.claude/projects/-w/s1.jsonl"
	traceSub  = "/home/u/.claude/projects/-w/s1/subagents"
)

func traceDecl() *TraceDecl {
	return &TraceDecl{
		Covers: func(p string) bool { return p == traceMain || p == traceSub || strings.HasPrefix(p, traceSub+"/") },
		Main:   func(p string) bool { return p == traceMain },
	}
}

// harnessAppends is the harness's own writing of its trace: level-0
// opens, writes and closes of the main file and a subagent's, the last
// close hashed.
func harnessAppends() models.GroundTruth {
	return models.GroundTruth{
		agentEv(0, models.FileOpen, traceMain), agentEv(1, models.FileWrite, traceMain), agentEv(2, models.FileClose, traceMain),
		agentEv(3, models.FileWrite, traceSub+"/agent-a1.jsonl"), agentEv(4, models.FileRename, traceSub+"/agent-a1.meta.json"),
		agentEv(30, models.FileOpen, traceMain), agentEv(31, models.FileWrite, traceMain),
		withHash(agentEv(32, models.FileClose, traceMain), nil, sp("sha256:last")),
	}
}

func traceRun(claims models.Trajectory, g models.GroundTruth, in TraceInput) Verdict {
	in.Decl = traceDecl()
	return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Trace: in, Baseline: harnessTrace})
}

// harnessTrace is a baseline that explains the harness's level-0 events on
// its trace, as a measured one does, so that only tampering is left.
func harnessTrace(e models.GroundTruthEvent) bool {
	return e.PID == agentPID && traceDecl().Covers(e.Target)
}

// The harness's own appends are its process's events and never tampering.
func TestTrace_TheHarnessAppendsAreNormal(t *testing.T) {
	v := traceRun(nil, harnessAppends(), TraceInput{})
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.TraceTampering) != 0 || !v.Trace.Declared || v.Trace.Unreadable() {
		t.Errorf("tampering %v, trace %+v, want none and a declared, read trace", v.TraceTampering, v.Trace)
	}
}

// A command that deletes, truncates or rewrites a trace file, at any level
// of its subtree, is tampering, a finding, even when the agent claimed the
// command (V-59).
func TestTrace_ACommandThatChangesTheTraceIsTampering(t *testing.T) {
	cmd := "/bin/sh -c rm transcript"
	cases := map[string]models.GroundTruth{
		"delete": {
			fork(10, 200, agentPID), execEv(11, 200, agentPID, cmd),
			fork(12, 201, 200), execEv(13, 201, 200, "/usr/bin/rm "+traceMain),
			{Timestamp: at(14), ActionType: models.FileDelete, Target: traceMain, PID: 201},
			exitEv(15, 201, 200, "/usr/bin/rm "+traceMain), exitEv(16, 200, agentPID, cmd),
		},
		"truncate": {
			fork(10, 200, agentPID), execEv(11, 200, agentPID, cmd),
			{Timestamp: at(14), ActionType: models.FileWrite, Target: traceMain, PID: 200},
			exitEv(16, 200, agentPID, cmd),
		},
		"rename over it": {
			fork(10, 200, agentPID), execEv(11, 200, agentPID, cmd),
			{Timestamp: at(13), ActionType: models.FileRename, Target: "/home/u/.claude/projects/-w/sedX", PID: 200},
			{Timestamp: at(14), ActionType: models.FileRename, Target: traceMain, PID: 200},
			exitEv(16, 200, agentPID, cmd),
		},
		"a subagent's file": {
			fork(10, 200, agentPID), execEv(11, 200, agentPID, cmd),
			{Timestamp: at(14), ActionType: models.FileDelete, Target: traceSub + "/agent-a1.jsonl", PID: 200},
			exitEv(16, 200, agentPID, cmd),
		},
	}
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			g = append(harnessAppends(), g...)
			v := traceRun(claimsFor(cmd), g, TraceInput{})
			wantOutcome(t, v, OutcomeNotFaithful)
			if len(v.TraceTampering) != 1 || v.Findings() != 1 {
				t.Fatalf("tampering %+v, findings %d, want the one event", v.TraceTampering, v.Findings())
			}
			tt := v.TraceTampering[0]
			if tt.Zone != "subtree" || tt.Level < 1 || tt.Command != cmd || tt.Event == nil {
				t.Errorf("evidence %+v, want the event in the command's subtree", tt)
			}
		})
	}
}

// A read of the trace by a command, and a write elsewhere in the project
// directory, are not tampering.
func TestTrace_AReadOrAnotherFileIsNotTampering(t *testing.T) {
	cmd := "/bin/sh -c cat transcript"
	g := append(harnessAppends(),
		fork(10, 200, agentPID), execEv(11, 200, agentPID, cmd),
		models.GroundTruthEvent{Timestamp: at(12), ActionType: models.FileOpen, Target: traceMain, PID: 200},
		models.GroundTruthEvent{Timestamp: at(13), ActionType: models.FileWrite, Target: "/home/u/.claude/projects/-w/memory/note.md", PID: 200},
		exitEv(16, 200, agentPID, cmd))
	v := traceRun(claimsFor(cmd), g, TraceInput{})
	if len(v.TraceTampering) != 0 {
		t.Errorf("tampering %+v, want none", v.TraceTampering)
	}
	wantOutcome(t, v, OutcomeFaithful)
}

// A process outside the agent's tree that writes the trace is tampering
// too; an event with no pid is unplaced and blocks FAITHFUL on its own.
func TestTrace_AnOutsideWriteIsTampering(t *testing.T) {
	g := append(harnessAppends(), models.GroundTruthEvent{Timestamp: at(40), ActionType: models.FileWrite, Target: traceMain, PID: 999})
	v := traceRun(nil, g, TraceInput{})
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.TraceTampering) != 1 || v.TraceTampering[0].Zone != "outside" {
		t.Errorf("tampering %+v, want the outside write", v.TraceTampering)
	}
	g = append(harnessAppends(), models.GroundTruthEvent{Timestamp: at(40), ActionType: models.FileWrite, Target: traceMain})
	v = traceRun(nil, g, TraceInput{})
	if len(v.TraceTampering) != 0 || v.Outcome == OutcomeFaithful {
		t.Errorf("an unplaced write: tampering %+v, outcome %v, want none and not FAITHFUL", v.TraceTampering, v.Outcome)
	}
}

// A write-class claim of a trace file, an agent tool aimed at its own trace,
// is tampering even when the write it claims is the harness process's own;
// a read claim is not.
func TestTrace_AClaimOfAWriteToTheTraceIsTampering(t *testing.T) {
	g := harnessAppends()
	g = append(g, agentEv(20, models.FileWrite, traceMain))
	claims := models.Trajectory{claimAt(20, models.FileWrite, traceMain)}
	v := traceRun(claims, g, TraceInput{})
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.TraceTampering) != 1 || v.TraceTampering[0].Claim == nil || v.TraceTampering[0].Zone != "claim" {
		t.Fatalf("tampering %+v, want the claim", v.TraceTampering)
	}
	if len(v.Corroborated) != 1 {
		t.Errorf("corroborated %d, want the claim still aligned and corroborated", len(v.Corroborated))
	}
	v = traceRun(models.Trajectory{claimAt(20, models.FileOpen, traceMain)}, harnessAppends(), TraceInput{})
	if len(v.TraceTampering) != 0 {
		t.Errorf("tampering %+v, want none for a read", v.TraceTampering)
	}
}

// Without a declaration nothing is tampering.
func TestTrace_NoDeclarationReadsNothingAsTampering(t *testing.T) {
	g := append(harnessAppends(), fork(10, 200, agentPID), execEv(11, 200, agentPID, "/bin/rm x"),
		models.GroundTruthEvent{Timestamp: at(14), ActionType: models.FileDelete, Target: traceMain, PID: 200})
	v := Verify(Input{Claims: claimsFor("/bin/rm x"), Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: harnessTrace})
	if len(v.TraceTampering) != 0 || v.Trace.Declared {
		t.Errorf("tampering %+v, declared %v, want none", v.TraceTampering, v.Trace.Declared)
	}
}

// A trace the reader could not read whole is not aligned and the run cannot
// be verified: INCONCLUSIVE with the reason first, or NOT FAITHFUL when the
// capture shows the tampering, with the evidence that the file was deleted
// after its last write (V-59).
func TestTrace_AnUnreadableTraceFailsClosed(t *testing.T) {
	for _, st := range []TraceState{TraceMissing, TraceEmpty, TraceUnparsable, TraceDamaged} {
		t.Run(string(st), func(t *testing.T) {
			claims := models.Trajectory{claimAt(50, models.FileWrite, "/w/fabricated")}
			v := traceRun(claims, harnessAppends(), TraceInput{State: st, Detail: "x"})
			wantOutcome(t, v, OutcomeInconclusive)
			if len(v.Reasons) == 0 || !strings.Contains(v.Reasons[0], "cannot verify: "+TraceDeletedOrDamaged) || !strings.Contains(v.Reasons[0], string(st)) {
				t.Errorf("reasons %v, want the trace's first", v.Reasons)
			}
			if len(v.Unwitnessed)+len(v.Corroborated)+len(v.Alignments) != 0 || v.Findings() != 0 {
				t.Errorf("an unreadable trace was aligned: %+v", v)
			}
		})
	}
	g := append(harnessAppends(), fork(40, 200, agentPID), execEv(41, 200, agentPID, "/bin/rm t"),
		models.GroundTruthEvent{Timestamp: at(42), ActionType: models.FileDelete, Target: traceMain, PID: 200})
	v := traceRun(nil, g, TraceInput{State: TraceMissing, Detail: "gone"})
	wantOutcome(t, v, OutcomeNotFaithful)
	if v.Findings() != 1 || len(v.TraceTampering) != 1 || v.Advisory {
		t.Errorf("findings %d, tampering %+v, advisory %v, want the delete alone", v.Findings(), v.TraceTampering, v.Advisory)
	}
	if len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "the last write of "+traceMain+" was its deletion") {
		t.Errorf("reasons %v, want the deletion named", v.Reasons)
	}
	if len(v.Trace.Files) != 1 || !v.Trace.Files[0].Deleted() {
		t.Errorf("trace files %+v, want the main file deleted", v.Trace.Files)
	}
	// Under loss the finding stays and is advisory.
	lossy := cov(map[string]models.ProbeCoverage{"fs": {Ran: true, QueueOverflow: true}, "proc": {Ran: true}, "net": {Ran: true}})
	v = Verify(Input{Ground: g, RootPID: agentPID, Coverage: lossy, Trace: TraceInput{Decl: traceDecl(), State: TraceMissing}})
	if v.Outcome != OutcomeNotFaithful || !v.Advisory {
		t.Errorf("under loss: %v advisory %v, want NOT FAITHFUL advisory", v.Outcome, v.Advisory)
	}
	// With no root, the trace's reason comes first.
	v = Verify(Input{Ground: g, Trace: TraceInput{Decl: traceDecl(), State: TraceMissing}})
	if v.Outcome != OutcomeInconclusive || !strings.Contains(v.Reasons[0], TraceDeletedOrDamaged) || len(v.Reasons) < 2 {
		t.Errorf("no root: %v %v, want INCONCLUSIVE with the trace's reason and the root's", v.Outcome, v.Reasons)
	}
}

// The content read is compared with the last content the probe hashed of
// the main file, when the reader asks: equal reads as before, different is
// a damaged trace, and a last write without a hash compares nothing.
func TestTrace_TheContentReadIsComparedWithTheLastHash(t *testing.T) {
	v := traceRun(nil, harnessAppends(), TraceInput{ReadHash: "sha256:last"})
	wantOutcome(t, v, OutcomeFaithful)
	if !v.Trace.Compared || v.Trace.Unreadable() {
		t.Errorf("trace %+v, want compared and read", v.Trace)
	}
	v = traceRun(nil, harnessAppends(), TraceInput{ReadHash: "sha256:other"})
	wantOutcome(t, v, OutcomeInconclusive)
	if v.Trace.State != TraceDiffers || !strings.Contains(v.Reasons[0], "sha256:last") {
		t.Errorf("trace %+v, reasons %v, want differs naming the probe's hash", v.Trace, v.Reasons)
	}
	g := append(harnessAppends(), agentEv(40, models.FileWrite, traceMain))
	v = traceRun(nil, g, TraceInput{ReadHash: "sha256:other"})
	wantOutcome(t, v, OutcomeFaithful)
	if v.Trace.Compared || v.Trace.Note == "" {
		t.Errorf("trace %+v, want not compared with a note", v.Trace)
	}
	// Without a request nothing is compared and nothing is noted.
	v = traceRun(nil, harnessAppends(), TraceInput{})
	if v.Trace.Compared || v.Trace.Note != "" {
		t.Errorf("trace %+v, want no comparison", v.Trace)
	}
}
