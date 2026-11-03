package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// V-85: an agy session states no version, so the version-gated
// declarations take the one --agent-version passes, as the capture
// recorded it. On the 1.4.7 fixture the token renewal is then declared
// housekeeping and the run is FAITHFUL, with and without --strict-version;
// without the flag nothing is declared and the renewal's POST is
// Unrecorded, as before.
func TestTheRecordedVersionKeysTheDeclarationsOfASessionWithoutOne(t *testing.T) {
	const dir = "../../pkg/agent/gemini/testdata/paired-agy-1.4.7-basic"
	controls, _ := filepath.Glob(filepath.Join(dir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range controls {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f, err := models.ParseGroundTruthFile(data)
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, f)
	}
	a, _ := agent.Lookup("gemini")
	b, err := agent.Capture(a, "1.4.7", runs, t0, agent.CaptureOptions{Exclude: []string{": agent-trace-control-marker"}, MinAgreement: 0.2})
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "baseline.json")
	if err := agent.SaveBaseline(base, b); err != nil {
		t.Fatal(err)
	}
	args := []string{"--agent", "gemini", "--trajectory", filepath.Join(dir, "basic.conversation.db"), "--ground-truth", filepath.Join(dir, "basic.ground_truth.json"), "--baseline", base}
	for _, extra := range [][]string{{"--agent-version", "1.4.7"}, {"--agent-version", "1.4.7", "--strict-version"}} {
		code, out, errOut := verify(t, append(append([]string{}, args...), extra...)...)
		if code != 0 || !strings.Contains(out, "  Declared harness housekeeping: 2  (") ||
			!strings.Contains(out, "net_request    POST https://oauth2.googleapis.com/token\n") ||
			!strings.Contains(out, "Unrecorded:   0  (") || !strings.Contains(out, "VERDICT: FAITHFUL") {
			t.Errorf("%v: exit %d, stderr %s\n%s", extra, code, errOut, out)
		}
	}
	code, out, errOut := verify(t, args...)
	if code != 1 || strings.Contains(out, "housekeeping") || !strings.Contains(out, "Unrecorded:   1  (") || !strings.Contains(out, "VERDICT: NOT FAITHFUL") {
		t.Errorf("without --agent-version: exit %d, stderr %s\n%s", code, errOut, out)
	}
}

// A session that states its version decides alone: DeclarationVersion
// takes the recorded version only when the session states none.
func TestDeclarationVersionPrefersTheSession(t *testing.T) {
	for _, c := range []struct{ session, recorded, want string }{
		{"2.1.306", "", "2.1.306"},
		{"2.1.306", "2.1.305", "2.1.306"},
		{"", "1.4.7", "1.4.7"},
		{"", "", ""},
	} {
		if got := agent.DeclarationVersion(c.session, c.recorded); got != c.want {
			t.Errorf("DeclarationVersion(%q, %q) = %q, want %q", c.session, c.recorded, got, c.want)
		}
	}
}
