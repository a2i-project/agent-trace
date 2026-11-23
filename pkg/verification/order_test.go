package verification

import (
	"math/rand"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// openAfter is a level-0 open the fs probe read at ms, with its earliest
// moment at notBefore ms (P-52), or none when notBefore is negative.
func openAfter(notBefore, ms int, path string) models.GroundTruthEvent {
	e := agentEv(ms, models.FileOpen, path)
	if notBefore >= 0 {
		nb := at(notBefore)
		e.NotBefore = &nb
	}
	return e
}

// readThenSend claims a read of the secret, then a request; the capture
// holds the request at 150 ms and the read between notBefore and 260 ms.
func readThenSend(notBefore int) (models.Trajectory, models.GroundTruth) {
	tr := models.Trajectory{claimAt(0, models.FileOpen, "/w/secret"), claimAt(10, models.NetRequest, "POST https://x.example/up")}
	g := models.GroundTruth{agentEv(150, models.NetRequest, "POST https://x.example/up"), openAfter(notBefore, 260, "/w/secret")}
	return tr, g
}

// An agent that reports "read the secret, then sent the request" when the
// request went first is caught across the fs and net lanes once the probes'
// bounds make the inversion certain (V-106).
func TestVerify_AnOrderInversionAcrossLanesIsAFinding(t *testing.T) {
	tr, g := readThenSend(250)
	v := run(tr, g)
	wantOutcome(t, v, OutcomeNotFaithful)
	if len(v.OrderViolations) != 1 || v.Findings() != 1 {
		t.Fatalf("order violations = %+v, findings = %d, want one", v.OrderViolations, v.Findings())
	}
	o := v.OrderViolations[0]
	if o.Later.ActionType != models.NetRequest || o.Earlier.Target != "/w/secret" || o.EarlierEvent.Target != "/w/secret" || o.LaterEvent.ActionType != models.NetRequest {
		t.Errorf("violation = %+v, want the request reported against the read", o)
	}
	// Each lane alone is in order, so nothing else is found.
	if len(v.Corroborated) != 2 || len(v.Unrecorded)+len(v.Unwitnessed)+len(v.Mismatched) != 0 {
		t.Errorf("alignment changed: %+v", v)
	}
}

// Only an inversion the bounds make certain is a finding: a file event with
// no earliest moment, or one whose earliest moment is before the request,
// may have come first. A kernel-stamped event (NotBefore equal to its
// timestamp) tightens the check with no other change (V-106).
func TestVerify_OnlyACertainInversionIsAnOrderFinding(t *testing.T) {
	for _, c := range []struct {
		name      string
		notBefore int
		want      int
	}{
		{"no earliest moment", -1, 0},
		{"earliest moment before the request", 100, 0},
		{"earliest moment equal to the request", 150, 0},
		{"earliest moment after the request", 151, 1},
		{"kernel-stamped", 260, 1},
	} {
		tr, g := readThenSend(c.notBefore)
		if v := run(tr, g); len(v.OrderViolations) != c.want {
			t.Errorf("%s: %d order violations, want %d", c.name, len(v.OrderViolations), c.want)
		}
	}
	// In the claimed order nothing is found, whatever the bounds.
	tr := models.Trajectory{claimAt(0, models.NetRequest, "POST https://x.example/up"), claimAt(10, models.FileOpen, "/w/secret")}
	_, g := readThenSend(260)
	if v := run(tr, g); len(v.OrderViolations) != 0 {
		t.Errorf("honest order: %+v", v.OrderViolations)
	}
}

// Claims of one parallel block have no order among themselves (V-32), and
// claims of different threads have none at all (V-107).
func TestVerify_BlocksAndThreadsAreNotOrdered(t *testing.T) {
	tr, g := readThenSend(250)
	tr[0].BlockID, tr[1].BlockID = "m1", "m1"
	if v := run(tr, g); len(v.OrderViolations) != 0 {
		t.Errorf("one block: %+v", v.OrderViolations)
	}
	tr, g = readThenSend(250)
	tr[1].ThreadID = "subagent-1"
	if v := run(tr, g); len(v.OrderViolations) != 0 {
		t.Errorf("two threads: %+v", v.OrderViolations)
	}
	// A claim of another thread between two claims of the main thread does
	// not break their order.
	tr, g = readThenSend(250)
	other := claimAt(5, models.NetConnect, "y.example:443")
	other.ThreadID = "subagent-1"
	tr = models.Trajectory{tr[0], other, tr[1]}
	g = append(g, agentEv(100, models.NetConnect, "y.example:443"))
	if v := run(tr, g); len(v.OrderViolations) != 1 {
		t.Errorf("main thread around a subagent's claim: %d violations, want 1", len(v.OrderViolations))
	}
}

// commandThenRead claims a command, then a read; the command execs at 10 ms,
// writes beneath it at writeMS and exits at exitMS, and the read's open lies
// between 200 and 210 ms.
func commandThenRead(writeMS, exitMS int, background bool) (models.Trajectory, models.GroundTruth) {
	cmd := claimAt(0, models.ProcessExec, "/bin/sh -c work")
	cmd.Background = background
	tr := models.Trajectory{cmd, claimAt(20, models.FileOpen, "/w/in")}
	g := models.GroundTruth{
		fork(5, 200, agentPID), execEv(10, 200, agentPID, "/bin/sh -c work"),
		fork(11, 201, 200), execEv(12, 201, 200, "/bin/daemon"),
		fsEv(writeMS, 201, "/w/out"), exitAt(exitMS, 200),
		openAfter(200, 210, "/w/in"),
		fsEv(400, 201, "/w/late"), // the descendant, after its command's exit
	}
	nb := at(writeMS)
	g[4].NotBefore = &nb
	nb2 := at(400)
	g[7].NotBefore = &nb2
	return tr, g
}

// A command's events up to its exit are its own: a command still writing
// after the next claim's action ran beside it, which the claims deny. A
// background call is checked by its start only, and a descendant's event
// after the command's exit is not the command's (V-106, V-108).
func TestVerify_ACommandIsOrderedByItsEventsUpToItsExit(t *testing.T) {
	tr, g := commandThenRead(150, 160, false)
	if v := run(tr, g); len(v.OrderViolations) != 0 {
		t.Errorf("command done before the read: %+v", v.OrderViolations)
	}
	tr, g = commandThenRead(300, 350, false)
	v := run(tr, g)
	if len(v.OrderViolations) != 1 || v.OrderViolations[0].Later.Target != "/w/in" {
		t.Fatalf("command still writing after the read: %+v", v.OrderViolations)
	}
	if e := v.OrderViolations[0].EarlierEvent; e.ActionType != models.ProcessExit {
		t.Errorf("earlier event = %+v, want the command's exit, the last of its events", e)
	}
	tr, g = commandThenRead(300, 350, true)
	if v := run(tr, g); len(v.OrderViolations) != 0 {
		t.Errorf("background call: %+v", v.OrderViolations)
	}
}

// boundsAt makes a bounds value for the brute force: lo < 0 means unbounded.
func boundsAt(lo, hi int) bounds {
	if lo < 0 {
		return bounds{hi: at(hi)}
	}
	return bounds{lo: at(lo), hi: at(hi), bounded: true}
}

// bruteOrder is the order check written from its definition (V-106, V-107):
// two claims of one thread with events are ordered unless they share a
// block and every claim of the thread between them does too; a later claim
// y is checked against an earlier x when they are ordered and no claim of
// the thread with events lies ordered between them; y is a violation when
// some event of x began after every event of y ended.
func bruteOrder(cs []orderClaim) map[int]bool {
	ordered := func(i, j int) bool {
		if cs[i].block == "" || cs[i].block != cs[j].block {
			return true
		}
		for k := i + 1; k < j; k++ {
			if cs[k].thread == cs[j].thread && cs[k].block != cs[j].block {
				return true
			}
		}
		return false
	}
	out := map[int]bool{}
	for y := range cs {
		for x := 0; x < y; x++ {
			if cs[x].thread != cs[y].thread || len(cs[x].events) == 0 || len(cs[y].events) == 0 || !ordered(x, y) {
				continue
			}
			between := false
			for k := x + 1; k < y; k++ {
				if cs[k].thread == cs[y].thread && len(cs[k].events) > 0 && ordered(x, k) && ordered(k, y) {
					between = true
				}
			}
			if between {
				continue
			}
			for _, a := range cs[x].events {
				all := a.bounded
				for _, b := range cs[y].events {
					all = all && a.lo.After(b.hi)
				}
				if all {
					out[y] = true
				}
			}
		}
	}
	return out
}

func TestOrderViolationsAgreeWithBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for round := 0; round < 20000; round++ {
		n := 1 + rng.Intn(7)
		cs := make([]orderClaim, n)
		for i := range cs {
			cs[i].thread = []string{"", "", "s"}[rng.Intn(3)]
			cs[i].block = []string{"", "", "b1", "b2"}[rng.Intn(4)]
			for k := rng.Intn(4); k > 0; k-- {
				hi := rng.Intn(20)
				lo := hi - rng.Intn(6)
				if rng.Intn(4) == 0 {
					lo = -1
				}
				cs[i].events = append(cs[i].events, boundsAt(lo, hi))
			}
		}
		want := bruteOrder(cs)
		got := orderViolations(cs)
		seen := map[int]bool{}
		for _, p := range got {
			if seen[p.later] {
				t.Fatalf("round %d: claim %d reported twice: %+v", round, p.later, got)
			}
			seen[p.later] = true
			a, b := cs[p.earlier].events[p.earlierEvent], cs[p.later].events[p.laterEvent]
			if p.earlier >= p.later || !a.bounded || !a.lo.After(b.hi) {
				t.Fatalf("round %d: reported pair %+v does not show an inversion: %+v", round, p, cs)
			}
			for _, e := range cs[p.later].events {
				if e.hi.After(b.hi) {
					t.Fatalf("round %d: the later event is not the later claim's last: %+v", round, p)
				}
			}
		}
		if len(seen) != len(want) {
			t.Fatalf("round %d: got %v, brute force %v, claims %+v", round, seen, want, cs)
		}
		for y := range want {
			if !seen[y] {
				t.Fatalf("round %d: brute force flags %d, the check does not: %+v", round, y, cs)
			}
		}
	}
}
