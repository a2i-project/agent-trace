package verification

import (
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func item(call, hash string) models.ModelItemDigest {
	return models.ModelItemDigest{Type: "function_call_output", CallID: call, Hash: hash}
}

func wsRequest(prev string, items ...models.ModelItemDigest) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: time.Unix(1, 0), ActionType: models.NetRequest, Target: "WS https://chatgpt.com/backend-api/codex/responses",
		ModelRequest: &models.ModelRequestDigest{Type: "response.create", PreviousResponseID: prev, Items: items}}
}

func methodCoverage(state string) *models.Coverage {
	return &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"net": {Ran: true, Content: state, Responses: state,
		Diagnostics: &models.ProbeDiagnostics{ContentMethods: map[string]models.ContentMethodState{"tls-rustls-aead": {Requests: state, Responses: state}}}}}}
}

func TestCheckModelRequests(t *testing.T) {
	a, b, c := item("c1", "sha256:a"), item("c2", "sha256:b"), item("c3", "sha256:c")
	turn := models.GroundTruthEvent{ActionType: models.NetResponse, Response: &models.ResponseAttestation{WebSocket: &models.WebSocketSummary{ResponseIDs: []string{"r1"}}}}
	reqs := []ModelRequest{
		{Index: 0, ResponseID: "r1", Items: []models.ModelItemDigest{a}},
		{Index: 1, PreviousResponseID: "r1", ResponseID: "r2", Items: []models.ModelItemDigest{b, c}},
		{Index: 2, PreviousResponseID: "r2", Items: []models.ModelItemDigest{c}},
		{Index: 3, PreviousResponseID: "r3", Items: []models.ModelItemDigest{a}},
		{Index: 4, PreviousResponseID: "r4", Items: []models.ModelItemDigest{a, b}},
	}
	ground := models.GroundTruth{
		wsRequest("", a),
		turn,
		wsRequest("r1", c, b), // the record's items in another order
		wsRequest("r2", a),    // another item than the record's
		wsRequest("r4", b),    // a retry missing an item...
		wsRequest("r4", a, b), // ...and the request that matches
		wsRequest("r9", a),    // continues a response the record does not name
	}
	r := checkModelRequests(reqs, "tls-rustls-aead", ground, methodCoverage(models.ContentActive))
	want := []struct {
		ok     bool
		reason string
	}{
		{true, ""},
		{false, "another order"},
		{false, "lacks 1 of the record's items and carries 1"},
		{false, "no captured request continues response r3"},
		{true, ""},
	}
	for i, w := range want {
		got := r.Checks[i]
		if got.Corroborated != w.ok || !strings.Contains(got.Reason, w.reason) {
			t.Errorf("#%d: corroborated %v reason %q, want %v %q", i, got.Corroborated, got.Reason, w.ok, w.reason)
		}
	}
	if !r.Checks[0].ResponseSeen || r.Checks[1].ResponseSeen {
		t.Errorf("response seen: %v %v, want r1 seen and r2 not", r.Checks[0].ResponseSeen, r.Checks[1].ResponseSeen)
	}
	if len(r.Unrecorded) != 2 || r.Corroborated() != 2 {
		t.Errorf("unrecorded %d (the retry and the r9 request), corroborated %d", len(r.Unrecorded), r.Corroborated())
	}
	if m := r.Checks[2]; len(m.Missing) != 1 || m.Missing[0] != c || len(m.Extra) != 1 || m.Extra[0] != a {
		t.Errorf("missing %v extra %v", m.Missing, m.Extra)
	}

	off := checkModelRequests(reqs, "tls-rustls-aead", ground, methodCoverage(models.ContentAttachFailed))
	if off.Corroborated() != 0 || len(off.Unrecorded) != 0 || !strings.Contains(off.Checks[0].Reason, "did not read requests") {
		t.Errorf("method silent: %+v", off.Checks[0])
	}
	if checkModelRequests(nil, "m", ground, nil) != nil {
		t.Error("a record with no requests is checked")
	}
}

// The check is reported and never changes the outcome.
func TestModelRequestsDoNotChangeTheOutcome(t *testing.T) {
	in := Input{Coverage: methodCoverage(models.ContentActive), ModelRequestMethod: "tls-rustls-aead",
		ModelRequests: []ModelRequest{{Index: 0, Items: []models.ModelItemDigest{item("c", "sha256:x")}}}}
	base := Verify(Input{Coverage: in.Coverage})
	v := Verify(in)
	if v.Outcome != base.Outcome || v.ModelRequests == nil || v.ModelRequests.Checks[0].Corroborated {
		t.Errorf("outcome %s vs %s, report %+v", v.Outcome, base.Outcome, v.ModelRequests)
	}
}

// wsTurn is a WebSocket turn naming one response, with the given message
// types, at second s.
func wsTurn(s int64, id string, types ...string) models.GroundTruthEvent {
	ws := &models.WebSocketSummary{ResponseIDs: []string{id}, Types: map[string]int{}}
	for _, t := range types {
		ws.Types[t]++
	}
	return models.GroundTruthEvent{Timestamp: time.Unix(s, 0), ActionType: models.NetResponse, PID: 7,
		Target: "WS https://chatgpt.com/backend-api/codex/responses", Response: &models.ResponseAttestation{Status: 101, WebSocket: ws}}
}

// sentAt places a captured request at second s, from the turns' process.
func sentAt(s int64, e models.GroundTruthEvent) models.GroundTruthEvent {
	e.Timestamp, e.PID = time.Unix(s, 0), 7
	return e
}

// A warm-up (V-69) is set aside, and the request continuing it is joined
// to the recorded request continuing what the warm-up continued, one hop
// only.
func TestCheckModelRequestsWarmUps(t *testing.T) {
	a, b := item("c1", "sha256:a"), item("c2", "sha256:b")
	empty := []string{"response.created", "response.completed"}
	output := []string{"response.created", "response.output_item.added", "response.output_item.done", "response.completed"}
	first := []ModelRequest{{Index: 0, ResponseID: "r1", Items: []models.ModelItemDigest{a, b}}}
	cov := methodCoverage(models.ContentActive)
	cases := []struct {
		name           string
		reqs           []ModelRequest
		ground         models.GroundTruth
		corroborated   bool
		warm, unrec    int
		joinedViaWarm  bool
		reasonContains string
	}{
		{"a warm-up is skipped", first, models.GroundTruth{
			sentAt(1, wsRequest("")), wsTurn(2, "w1", empty...),
			sentAt(3, wsRequest("w1", a, b)), wsTurn(4, "r1", output...),
		}, true, 1, 0, true, ""},
		{"an empty request whose turn shows an output item is no warm-up", first, models.GroundTruth{
			sentAt(1, wsRequest("")), wsTurn(2, "w1", output...),
			sentAt(3, wsRequest("w1", a, b)), wsTurn(4, "r1", output...),
		}, false, 0, 1, false, "lacks 2 of the record's items"},
		{"a turn whose types overflowed is no warm-up", first, models.GroundTruth{
			sentAt(1, wsRequest("")), wsTurn(2, "w1", "response.created", "(other)"),
			sentAt(3, wsRequest("w1", a, b)), wsTurn(4, "r1", output...),
		}, false, 0, 1, false, "lacks 2"},
		{"a two-hop chain is refused", first, models.GroundTruth{
			sentAt(1, wsRequest("")), wsTurn(2, "w1", empty...),
			sentAt(3, wsRequest("w1")), wsTurn(4, "w2", empty...),
			sentAt(5, wsRequest("w2", a, b)), wsTurn(6, "r1", output...),
		}, false, 2, 1, false, "no captured request continues no response"},
		{"a warm-up whose response the record names is not skipped", []ModelRequest{
			{Index: 0, ResponseID: "w1", Items: []models.ModelItemDigest{a, b}},
			{Index: 1, PreviousResponseID: "w1", ResponseID: "r1", Items: []models.ModelItemDigest{a, b}},
		}, models.GroundTruth{
			sentAt(1, wsRequest("")), wsTurn(2, "w1", empty...),
			sentAt(3, wsRequest("w1", a, b)), wsTurn(4, "r1", output...),
		}, false, 0, 0, false, "lacks 2"},
		{"an empty request nothing continues is no warm-up", first, models.GroundTruth{
			sentAt(1, wsRequest("")), wsTurn(2, "w1", empty...),
			sentAt(3, wsRequest("w9", a, b)), wsTurn(4, "r1", output...),
		}, false, 0, 1, false, "lacks 2"},
	}
	for _, c := range cases {
		r := checkModelRequests(c.reqs, "tls-rustls-aead", c.ground, cov)
		got := r.Checks[0]
		if got.Corroborated != c.corroborated || !strings.Contains(got.Reason, c.reasonContains) {
			t.Errorf("%s: corroborated %v reason %q", c.name, got.Corroborated, got.Reason)
		}
		if len(r.WarmUps) != c.warm || len(r.Unrecorded) != c.unrec {
			t.Errorf("%s: %d warm-ups, %d unrecorded; want %d, %d", c.name, len(r.WarmUps), len(r.Unrecorded), c.warm, c.unrec)
		}
		if (got.WarmUp != nil) != c.joinedViaWarm {
			t.Errorf("%s: joined via a warm-up %v", c.name, got.WarmUp != nil)
		}
		if got.WarmUp != nil && got.Event.ModelRequest.PreviousResponseID != "w1" {
			t.Errorf("%s: joined %+v", c.name, got.Event.ModelRequest)
		}
	}
	// A warm-up whose response the record names: the second recorded
	// request is joined directly, and the first is compared with it.
	r := checkModelRequests(cases[4].reqs, "tls-rustls-aead", cases[4].ground, cov)
	if !r.Checks[1].Corroborated || r.Checks[1].WarmUp != nil {
		t.Errorf("the request continuing a named response: %+v", r.Checks[1])
	}
}

// Two connections of one process to one target interleave: a subagent's
// warm-up is sent before the main thread's turn arrives. That turn names a
// response a recorded request got, so it is not the warm-up's turn; the
// next one is (V-71).
func TestCheckModelRequestsInterleavedWarmUps(t *testing.T) {
	a, b, c, d := item("c1", "sha256:a"), item("c2", "sha256:b"), item("c3", "sha256:c"), item("c4", "sha256:d")
	empty := []string{"response.created", "response.completed"}
	output := []string{"response.created", "response.output_item.added", "response.output_item.done", "response.completed"}
	reqs := []ModelRequest{
		{Index: 0, ResponseID: "r1", Items: []models.ModelItemDigest{a, b}},
		{Index: 1, PreviousResponseID: "r1", ResponseID: "r2", Items: []models.ModelItemDigest{c}},
		{Index: 2, ResponseID: "s1", Items: []models.ModelItemDigest{d}},
	}
	ground := func(between string) models.GroundTruth {
		return models.GroundTruth{
			sentAt(1, wsRequest("")), wsTurn(2, "wm", empty...),
			sentAt(3, wsRequest("wm", a, b)), wsTurn(4, "r1", output...),
			sentAt(5, wsRequest("r1", c)),
			sentAt(6, wsRequest("")),
			wsTurn(7, between, output...),
			wsTurn(8, "ws", empty...),
			sentAt(9, wsRequest("ws", d)), wsTurn(10, "s1", output...),
		}
	}
	cov := methodCoverage(models.ContentActive)
	r := checkModelRequests(reqs, "tls-rustls-aead", ground("r2"), cov)
	if r.Corroborated() != 3 || len(r.WarmUps) != 2 || len(r.Unrecorded) != 0 {
		t.Fatalf("%d corroborated, %d warm-ups, %d unrecorded; checks %+v", r.Corroborated(), len(r.WarmUps), len(r.Unrecorded), r.Checks)
	}
	if w := r.Checks[2].WarmUp; w == nil || !w.Timestamp.Equal(time.Unix(6, 0)) {
		t.Errorf("the subagent's request joined via %+v", w)
	}
	// A turn between them naming a response no recorded request got is the
	// empty request's turn, as before: it shows an output item, so the
	// empty request is no warm-up.
	r = checkModelRequests(reqs, "tls-rustls-aead", ground("r9"), cov)
	if len(r.WarmUps) != 1 || r.Checks[2].Corroborated {
		t.Errorf("%d warm-ups; subagent check %+v", len(r.WarmUps), r.Checks[2])
	}
}
