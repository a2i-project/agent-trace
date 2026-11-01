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
