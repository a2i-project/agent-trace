package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// apiResponse is a net_response of the model API as the net probe records it
// (N-29, N-30): stamped at its status line, its target the request it
// answers, its record the status, the request-id header and the event counts
// of a complete stream.
func apiResponse(ms int, pid uint32, requestID string) models.GroundTruthEvent {
	return models.GroundTruthEvent{
		Timestamp: at(ms), ActionType: models.NetResponse, PID: pid,
		Target: "POST https://api.anthropic.com/v1/messages?beta=true",
		Response: &models.ResponseAttestation{
			Status: 200, RequestID: requestID, ContentType: "text/event-stream",
			BodyBytes: 4096, BodyHash: "sha256:00", End: at(ms + 900), Complete: true, Paired: true,
			SSE: &models.SSESummary{Events: 12, Types: map[string]int{"message_start": 1, "content_block_start": 2, "message_stop": 1}},
		},
	}
}

// responsesActive is a complete capture whose net probe validated its
// reading of responses.
func responsesActive() *models.Coverage {
	return cov(map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}, "net": {Ran: true, Responses: models.ContentActive}})
}

// V-45: a server-side call whose request id equals the request-id of exactly
// one complete, status-200 event stream that the agent's own process read
// from the model API host, in a capture that validated its response reading,
// is corroborated as a call. Anything else leaves it uncorroborated with the
// reason, and neither changes the outcome.
func TestVerify_AServerSideCallIsCorroboratedByItsResponse(t *testing.T) {
	call := ServerCall{Tool: "WebSearch", ID: "toolu_1", RequestID: "req_1", Host: "api.anthropic.com", Timestamp: at(1000)}
	edit := func(f func(*models.GroundTruthEvent)) models.GroundTruth {
		e := apiResponse(10, agentPID, "req_1")
		r := *e.Response
		sse := *r.SSE
		r.SSE = &sse
		e.Response = &r
		f(&e)
		return models.GroundTruth{e}
	}
	for _, c := range []struct {
		name   string
		call   ServerCall
		ground models.GroundTruth
		cov    *models.Coverage
		reason string // "" for corroborated
	}{
		{"the response that issued the call", call, models.GroundTruth{apiResponse(10, agentPID, "req_1"), apiResponse(2000, agentPID, "req_2")}, responsesActive(), ""},
		{"no request id in the session", ServerCall{Tool: "WebSearch", ID: "toolu_1", Host: "api.anthropic.com"}, models.GroundTruth{apiResponse(10, agentPID, "")}, responsesActive(), "records no request id"},
		{"response reading not validated", call, models.GroundTruth{apiResponse(10, agentPID, "req_1")}, completeCov(), "did not validate"},
		{"no coverage record", call, models.GroundTruth{apiResponse(10, agentPID, "req_1")}, nil, "did not validate"},
		{"no response carries it", call, models.GroundTruth{apiResponse(10, agentPID, "req_2")}, responsesActive(), "no response"},
		{"two responses carry it", call, models.GroundTruth{apiResponse(10, agentPID, "req_1"), apiResponse(20, agentPID, "req_1")}, responsesActive(), "2 responses"},
		{"a command's process read it", call, models.GroundTruth{fork(1, 200, agentPID), execEv(2, 200, agentPID, "/usr/bin/curl"), apiResponse(10, 200, "req_1")}, responsesActive(), "no response"},
		{"another host", call, edit(func(e *models.GroundTruthEvent) { e.Target = "GET https://evil.example/r" }), responsesActive(), "no request to the model API host"},
		{"a host the call does not name", ServerCall{Tool: "WebSearch", ID: "toolu_1", RequestID: "req_1"}, models.GroundTruth{apiResponse(10, agentPID, "req_1")}, responsesActive(), "no request to the model API host"},
		{"a superstring of the host", call, edit(func(e *models.GroundTruthEvent) { e.Target = "POST https://api.anthropic.com.evil.example/v1/messages" }), responsesActive(), "no request to the model API host"},
		{"unpaired", call, edit(func(e *models.GroundTruthEvent) { e.Response.Paired = false; e.Target = "https://api.anthropic.com" }), responsesActive(), "no request to the model API host"},
		{"status 529", call, edit(func(e *models.GroundTruthEvent) { e.Response.Status = 529 }), responsesActive(), "status 529"},
		{"incomplete", call, edit(func(e *models.GroundTruthEvent) { e.Response.Complete = false }), responsesActive(), "did not end"},
		{"truncated", call, edit(func(e *models.GroundTruthEvent) { e.Response.Truncated = true }), responsesActive(), "did not end"},
		{"not an event stream", call, edit(func(e *models.GroundTruthEvent) { e.Response.SSE = nil }), responsesActive(), "not an event stream"},
		{"stream count overflowed", call, edit(func(e *models.GroundTruthEvent) { e.Response.SSE.Overflow = true }), responsesActive(), "not an event stream"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := Verify(Input{Ground: c.ground, RootPID: agentPID, Coverage: c.cov, ServerCalls: []ServerCall{c.call}})
			if len(v.ServerCalls) != 1 {
				t.Fatalf("%d server-call checks, want 1", len(v.ServerCalls))
			}
			chk := v.ServerCalls[0]
			if chk.Corroborated != (c.reason == "") || !strings.Contains(chk.Reason, c.reason) || (c.reason == "") != (chk.Reason == "") {
				t.Errorf("corroborated %v, reason %q; want reason containing %q", chk.Corroborated, chk.Reason, c.reason)
			}
			if chk.Corroborated && (chk.Response == nil || chk.Response.Response.RequestID != "req_1") {
				t.Errorf("response %+v, want the joined one", chk.Response)
			}
			without := Verify(Input{Ground: c.ground, RootPID: agentPID, Coverage: c.cov})
			if v.Outcome != without.Outcome || v.Findings() != without.Findings() || len(v.Corroborated) != 0 {
				t.Errorf("outcome %s, findings %d, corroborated claims %d; want the run's own %s and %d: a server-side call is never aligned", v.Outcome, v.Findings(), len(v.Corroborated), without.Outcome, without.Findings())
			}
		})
	}
}

// The outcome never depends on a server-side call: a run FAITHFUL without
// them is FAITHFUL with a corroborated one and with one that is not, and a
// run without calls has no checks.
func TestVerify_ServerSideCallsNeverChangeTheOutcome(t *testing.T) {
	g := models.GroundTruth{agentEv(0, models.FileWrite, "/w/a"), apiResponse(10, agentPID, "req_1")}
	claims := models.Trajectory{claimAt(0, models.FileWrite, "/w/a")}
	base := Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: responsesActive()})
	if base.Outcome != OutcomeFaithful || base.ServerCalls != nil {
		t.Fatalf("outcome %s, checks %v; want FAITHFUL and none", base.Outcome, base.ServerCalls)
	}
	for _, id := range []string{"req_1", "req_missing"} {
		v := Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: responsesActive(),
			ServerCalls: []ServerCall{{Tool: "WebSearch", ID: "t", RequestID: id, Host: "api.anthropic.com"}}})
		if v.Outcome != base.Outcome || v.Findings() != 0 || len(v.Reasons) != 0 {
			t.Errorf("%s: outcome %s, findings %d, reasons %v; want the run's own", id, v.Outcome, v.Findings(), v.Reasons)
		}
	}
}

func TestTargetHost(t *testing.T) {
	for target, want := range map[string]string{
		"POST https://api.anthropic.com/v1/messages?beta=true": "api.anthropic.com",
		"POST https://api.anthropic.com?x=1":                   "api.anthropic.com",
		"GET https://h.example:8443/p":                         "h.example:8443",
		"https://api.anthropic.com":                            "",
		"api.anthropic.com":                                    "",
	} {
		if got := targetHost(target); got != want {
			t.Errorf("targetHost(%q) = %q, want %q", target, got, want)
		}
	}
}
