package models

import "testing"

func TestCanonicalNetTarget_DefaultPortOmitted(t *testing.T) {
	got := CanonicalNetTarget("GET", "API.Example.com", 443, "/v1/chat", "")
	want := "GET https://api.example.com/v1/chat"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalNetTarget_NonDefaultPortKept(t *testing.T) {
	got := CanonicalNetTarget("GET", "example.com", 8443, "/v1/chat", "")
	want := "GET https://example.com:8443/v1/chat"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalNetTarget_UnspecifiedPortOmitted(t *testing.T) {
	got := CanonicalNetTarget("GET", "example.com", 0, "/v1/chat", "")
	want := "GET https://example.com/v1/chat"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalNetTarget_QueryOrderPreserved(t *testing.T) {
	got := CanonicalNetTarget("GET", "example.com", 443, "/search", "z=1&a=2")
	want := "GET https://example.com/search?z=1&a=2"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalNetTarget_NoQuery(t *testing.T) {
	got := CanonicalNetTarget("POST", "example.com", 443, "/v1/messages", "")
	want := "POST https://example.com/v1/messages"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCanonicalNetTarget_GroundTruthAndTrajectoryAgree exercises the actual
// requirement of the network probe (docs/architecture/13_probe_net.md): a ground-truth triple (host from SNI,
// port from the connection, path/query from the parsed HTTP request line)
// and the equivalent trajectory-side URL (e.g. from a WebFetch tool_use
// input) must canonicalize identically for strict-equality matching to work.
func TestCanonicalNetTarget_GroundTruthAndTrajectoryAgree(t *testing.T) {
	groundTruth := CanonicalNetTarget("GET", "artificialintelligenceact.eu", 443, "/article/68/", "")
	trajectory := CanonicalNetTarget("GET", "ArtificialIntelligenceAct.eu", 443, "/article/68/", "")
	if groundTruth != trajectory {
		t.Errorf("ground truth %q != trajectory %q", groundTruth, trajectory)
	}
}
