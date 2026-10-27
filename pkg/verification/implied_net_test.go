package verification

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

const (
	preflight = "GET https://api.anthropic.com/api/web/domain_info?domain=man7.org"
	fetchURL  = "GET https://man7.org/linux/man-pages/man7/fanotify.7.html"
)

// impliedNet is a harness-implied request or connection (V-52) over the
// call's interval [from, to].
func impliedNet(from, to int, typ models.ActionType, target string) models.TrajectoryEntry {
	end := at(to)
	return models.TrajectoryEntry{Timestamp: at(from), End: &end, ActionType: typ, Target: target, ImpliedBy: "WebFetch https://man7.org/x", Tool: "WebFetch"}
}

// webFetchClaims are a WebFetch's claims: the harness's domain check,
// implied, then the agent's connection and request.
func webFetchClaims() models.Trajectory {
	connect, request := claimAt(5, models.NetConnect, "man7.org"), claimAt(5, models.NetRequest, fetchURL)
	end := at(3000)
	connect.End, request.End = &end, &end
	return models.Trajectory{impliedNet(5, 3000, models.NetRequest, preflight), connect, request}
}

// A WebFetch's run: the domain check, then the connection and the fetch, all
// by the agent's own process.
func webFetchRun() models.GroundTruth {
	return models.GroundTruth{
		agentEv(10, models.NetRequest, preflight),
		agentEv(380, models.NetConnect, "man7.org"),
		agentEv(440, models.NetRequest, fetchURL),
	}
}

// The harness's domain check pairs with its implied claim: reported as
// harness implied, not as the agent's, and the run is FAITHFUL; without the
// claim the same request is an omission. Unpaired, the claim costs nothing.
func TestVerify_AWebFetchsDomainCheckIsHarnessImplied(t *testing.T) {
	v := run(webFetchClaims(), webFetchRun())
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Corroborated) != 2 || len(v.HarnessImplied) != 1 || v.HarnessImplied[0].Event.Target != preflight {
		t.Errorf("corroborated %v, implied %v", v.Corroborated, v.HarnessImplied)
	}
	v = run(webFetchClaims()[1:], webFetchRun())
	if v.Outcome != OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != preflight {
		t.Errorf("without the implied claim: outcome %s, unrecorded %v", v.Outcome, v.Unrecorded)
	}
	v = run(webFetchClaims(), webFetchRun()[1:])
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.HarnessImpliedUnpaired) != 1 || len(v.Unwitnessed) != 0 {
		t.Errorf("unpaired %v, unwitnessed %v, want the domain check unpaired at no cost", v.HarnessImpliedUnpaired, v.Unwitnessed)
	}
}

// An implied request or connection pairs only with an event of its own type
// whose target is exactly its own, by the agent's own process, inside the
// call's interval; every other event stays an omission and the claim stays
// unpaired, never Mismatched.
func TestVerify_AnImpliedRequestPairsOnlyWithItsExactTarget(t *testing.T) {
	for name, e := range map[string]models.GroundTruthEvent{
		"another domain":      agentEv(10, models.NetRequest, "GET https://api.anthropic.com/api/web/domain_info?domain=evil.example"),
		"another letter case": agentEv(10, models.NetRequest, "GET https://api.anthropic.com/api/web/domain_info?domain=MAN7.org"),
		"another method":      agentEv(10, models.NetRequest, "POST https://api.anthropic.com/api/web/domain_info?domain=man7.org"),
		"a connection":        agentEv(10, models.NetConnect, "api.anthropic.com"),
		"a truncated target": func() models.GroundTruthEvent {
			e := agentEv(10, models.NetRequest, preflight)
			e.TargetTruncated = true
			return e
		}(),
		"a body": func() models.GroundTruthEvent {
			e := agentEv(10, models.NetRequest, preflight)
			e.RequestHash = sp("sha256:00")
			return e
		}(),
		"outside the interval":  agentEv(9000, models.NetRequest, preflight),
		"before the call began": agentEv(-2000, models.NetRequest, preflight),
	} {
		t.Run(name, func(t *testing.T) {
			g := append(models.GroundTruth{e}, webFetchRun()[1:]...)
			v := run(webFetchClaims(), g)
			if len(v.HarnessImplied) != 0 || len(v.Mismatched) != 0 || len(v.HarnessImpliedUnpaired) != 1 {
				t.Fatalf("implied %v, mismatched %v, unpaired %v", v.HarnessImplied, v.Mismatched, v.HarnessImpliedUnpaired)
			}
			if len(v.Unrecorded) != 1 || v.Outcome != OutcomeNotFaithful {
				t.Errorf("outcome %s, unrecorded %v: the event must stay an omission", v.Outcome, v.Unrecorded)
			}
		})
	}
}

// A command's request is content of its subtree, not the agent's own, so an
// implied request never pairs with it: the curl's request is explained by its
// claimed command and the implied claim stays unpaired.
func TestVerify_AnImpliedRequestNeverPairsWithACommandsRequest(t *testing.T) {
	curl := claimAt(5, models.ProcessExec, "curl https://api.anthropic.com/api/web/domain_info?domain=man7.org")
	end := at(3000)
	curl.End = &end
	tr := models.Trajectory{curl, impliedNet(5, 3000, models.NetRequest, preflight)}
	g := models.GroundTruth{
		fork(6, 300, agentPID), execEv(7, 300, agentPID, curl.Target),
		{Timestamp: at(10), ActionType: models.NetRequest, Target: preflight, PID: 300},
	}
	v := run(tr, g)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.HarnessImplied) != 0 || len(v.HarnessImpliedUnpaired) != 1 {
		t.Errorf("implied %v, unpaired %v", v.HarnessImplied, v.HarnessImpliedUnpaired)
	}
}

// A fetch the harness may serve from its cache: its connection and request
// are implied, pair when the harness fetched after all, and cost nothing when
// it did not. An ordinary claim of the same request wins it over an implied
// one, whichever comes first.
func TestVerify_ACachedFetchIsOptional(t *testing.T) {
	tr := models.Trajectory{impliedNet(5, 3000, models.NetConnect, "man7.org"), impliedNet(5, 3000, models.NetRequest, fetchURL)}
	v := run(tr, webFetchRun()[1:])
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.HarnessImplied) != 2 || len(v.Corroborated) != 0 {
		t.Errorf("implied %v, corroborated %v", v.HarnessImplied, v.Corroborated)
	}
	v = run(tr, nil)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.HarnessImpliedUnpaired) != 2 || len(v.Unwitnessed) != 0 {
		t.Errorf("unpaired %v, unwitnessed %v", v.HarnessImpliedUnpaired, v.Unwitnessed)
	}
	request := claimAt(5, models.NetRequest, fetchURL)
	for name, c := range map[string]models.Trajectory{
		"implied first": {impliedNet(5, 3000, models.NetRequest, fetchURL), request},
		"implied last":  {request, impliedNet(5, 3000, models.NetRequest, fetchURL)},
	} {
		a := laneOf(t, mustAlign(t, c, models.GroundTruth{agentEv(440, models.NetRequest, fetchURL)}), LaneNet)
		if a.Ambiguous || a.Optimal != 1 {
			t.Errorf("%s: ambiguous %v, optimal %d", name, a.Ambiguous, a.Optimal)
		}
		for _, e := range a.Edits {
			if e.Kind == EditMatch && implied(*e.Claim) {
				t.Errorf("%s: the implied claim took the request from the ordinary one: %+v", name, a.Edits)
			}
		}
	}
}
