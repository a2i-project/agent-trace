package claudecode

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// webSearchSession is a transcript of 2.1.306 with two WebSearch calls, the
// first issued by the response req_A, the second by req_B, in the shape a
// real transcript has them: the requestId on the assistant record that holds
// the tool_use, and a result with the query and the results.
const webSearchSession = `{"type":"assistant","timestamp":"2026-10-26T10:00:01Z","sessionId":"s","version":"2.1.306","requestId":"req_A","message":{"id":"msg_1","content":[{"type":"tool_use","id":"toolu_1","name":"WebSearch","input":{"query":"agent trace"}}]}}
{"type":"user","timestamp":"2026-10-26T10:00:05Z","sessionId":"s","version":"2.1.306","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"results"}]},"toolUseResult":{"query":"agent trace","results":[],"durationSeconds":3.1,"searchCount":1}}
{"type":"assistant","timestamp":"2026-10-26T10:00:06Z","sessionId":"s","version":"2.1.306","requestId":"req_B","message":{"id":"msg_2","content":[{"type":"tool_use","id":"toolu_2","name":"WebSearch","input":{"query":"other"}}]}}
{"type":"user","timestamp":"2026-10-26T10:00:09Z","sessionId":"s","version":"2.1.306","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_2","content":"results"}]},"toolUseResult":{"query":"other","results":[],"durationSeconds":2.0,"searchCount":1}}
`

// A WebSearch call stays non-effectful, claims nothing, and is reported as a
// server-side call with the requestId of the record that issued it and the
// model API host; the verifier corroborates the one whose response the
// capture read whole and leaves the other uncorroborated (V-45).
func TestAWebSearchIsAServerSideCallJoinedByItsRequestID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(path, []byte(webSearchSession), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, rep, err := Adapter{}.Parse(path)
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("parse: %v %v", err, rep.ParseErrors)
	}
	if len(tr) != 0 || rep.UnmappedByTool["WebSearch"] != 2 || len(rep.ServerCalls) != 2 {
		t.Fatalf("claims %v, unmapped %v, server calls %+v; want no claim, two non-effectful WebSearch calls reported as server-side calls", tr, rep.UnmappedByTool, rep.ServerCalls)
	}
	first := rep.ServerCalls[0]
	if first.Tool != "WebSearch" || first.ID != "toolu_1" || first.RequestID != "req_A" || first.Host != "api.anthropic.com" ||
		!first.Timestamp.Equal(time.Date(2026, 10, 26, 10, 0, 1, 0, time.UTC)) {
		t.Errorf("first call %+v", first)
	}

	const root = 100
	t0 := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	resp := models.GroundTruthEvent{Timestamp: t0, ActionType: models.NetResponse, PID: root,
		Target: "POST https://api.anthropic.com/v1/messages?beta=true",
		Response: &models.ResponseAttestation{Status: 200, RequestID: "req_A", ContentType: "text/event-stream", BodyBytes: 900,
			End: t0.Add(time.Second), Complete: true, Paired: true, SSE: &models.SSESummary{Events: 9, Types: map[string]int{"message_stop": 1}}}}
	g := models.GroundTruthFile{RootPID: root, Events: models.GroundTruth{resp},
		Coverage: &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{
			"fs": {Ran: true}, "proc": {Ran: true}, "net": {Ran: true, Responses: models.ContentActive}}}}
	in := agent.Prepare(Adapter{}, tr, g, nil, verification.Options{})
	in.ServerCalls = rep.ServerCalls
	v := verification.Verify(in)
	if len(v.ServerCalls) != 2 || !v.ServerCalls[0].Corroborated || v.ServerCalls[1].Corroborated || v.ServerCalls[1].Reason == "" {
		t.Errorf("checks %+v; want the first corroborated as a call and the second not, with its reason", v.ServerCalls)
	}
	if v.Outcome != verification.OutcomeFaithful {
		t.Errorf("outcome %s, want FAITHFUL: a server-side call changes no outcome", v.Outcome)
	}
}
