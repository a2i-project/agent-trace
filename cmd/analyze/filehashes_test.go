package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// A run's hashed closes by source (P-50) come from the manifest's scale
// record, and the report lists them per run only when some run has them
// (I-154).
func TestTheReportListsHashedClosesBySource(t *testing.T) {
	var rec RunRecord
	if err := json.Unmarshal([]byte(`{"agent": "claude-code", "scale": {"events": {"total": 4}, "file_hashes": {"mode": "kernel", "kernel": 7, "userspace": 2, "fallbacks": {"writer_held": 1, "raced": 1}, "lost": 0, "sync_timeouts": 1}}}`), &rec); err != nil {
		t.Fatal(err)
	}
	sc := (&Campaign{Dir: t.TempDir()}).sessionCost(rec, &Session{})
	if sc.FileHashes == nil || sc.FileHashes.Kernel != 7 || sc.FileHashes.Fallbacks["raced"] != 1 {
		t.Fatalf("session cost %+v", sc.FileHashes)
	}
	var m md
	reportFileHashes(&m, &Results{Runs: []RunOutput{
		{ID: "claude-code-2.1.306/basic/run-01", Agent: "claude-code", Version: "2.1.306", Task: "basic", Cost: sc},
		{ID: "claude-code-2.1.306/basic/run-02", Agent: "claude-code", Version: "2.1.306", Task: "basic", Cost: &SessionCost{}},
	}})
	got := m.String()
	if !strings.Contains(got, "### Hashed closes by source (P-50)") ||
		!strings.Contains(got, "| `claude-code-2.1.306/basic/run-01` | claude-code | 2.1.306 | basic | kernel | 7 | 2 | raced 1, writer_held 1 | 0 | 1 |") ||
		strings.Contains(got, "run-02") {
		t.Errorf("report:\n%s", got)
	}

	// No run with the record: no section.
	var none md
	reportFileHashes(&none, &Results{Runs: []RunOutput{{ID: "x", Cost: &SessionCost{FileHashes: (*models.FileHashCounts)(nil)}}}})
	if none.String() != "" {
		t.Errorf("a section without records:\n%s", none.String())
	}
}
