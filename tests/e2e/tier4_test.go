package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

func TestTier4_E2E_NotFaithful_ContentSubstitution(t *testing.T) {
	skipUnprivileged(t)

	c := runFileOnly(t)
	if verdict := c.verify(c.tr); verdict.Outcome != verification.OutcomeFaithful {
		logVerdict(t, verdict)
		t.Fatalf("honest content-hashed trajectory was not faithful: %s", verdict.Outcome)
	}

	// simagent's first claim is the open of file1.txt, the file it writes.
	target := c.tr[0].Target
	if filepath.Base(target) != "file1.txt" {
		t.Fatalf("first claim targets %s, want file1.txt", target)
	}
	trajectory := append(models.Trajectory{}, c.tr...)
	mutated := false
	for index := range trajectory {
		entry := &trajectory[index]
		if entry.ActionType != models.FileClose || entry.Target != target || entry.OutputHash == nil {
			continue
		}
		bogusHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		entry.OutputHash = &bogusHash
		mutated = true
		break
	}
	if !mutated {
		t.Fatalf("no content-hashed FileClose entry for %s", target)
	}

	verdict := c.verify(trajectory)
	if verdict.Outcome != verification.OutcomeNotFaithful {
		t.Fatalf("outcome = %s, want NOT FAITHFUL after substituting the content hash", verdict.Outcome)
	}
	for _, pair := range verdict.Mismatched {
		if pair.Entry.ActionType == models.FileClose && pair.Entry.Target == target {
			return
		}
	}
	logVerdict(t, verdict)
	t.Fatalf("content substitution for %s was not classified as Mismatched", target)
}

// TestTier4_E2E_RacedRewriteDropsStaleHash is the supplementary, timing-driven
// check for Fix 5 (the deterministic proof is TestObserver_RacedCloseDropsHash
// in pkg/probe/fs). A tight write/close/rewrite loop keeps overwriting the file
// while post-close hash goroutines are still in flight. The assertion is safe
// regardless of scheduling: any OutputHash the observer does attach to a
// FileClose for this path must be the hash of the file's final content -- never
// a stale intermediate. Post-fix, a close whose file was written again reports
// no hash instead.
func TestTier4_E2E_RacedRewriteDropsStaleHash(t *testing.T) {
	skipUnprivileged(t)

	workspace := t.TempDir()
	observer, err := fs.New(fs.Config{
		Path:         workspace,
		PathFilter:   workspace,
		PIDFilter:    int32(os.Getpid()),
		EventBufSize: 4096,
	})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	observer.Start()
	time.Sleep(200 * time.Millisecond)

	target := filepath.Join(workspace, "raced.txt")
	const iterations = 40
	var finalContent []byte
	for i := 0; i < iterations; i++ {
		finalContent = []byte(fmt.Sprintf("content-revision-%03d\n", i))
		if err := os.WriteFile(target, finalContent, 0o644); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	time.Sleep(700 * time.Millisecond)
	if err := observer.Stop(); err != nil {
		t.Fatalf("observer.Stop: %v", err)
	}

	validHashes := make(map[string]bool)
	for i := 0; i < iterations; i++ {
		contentBytes := []byte(fmt.Sprintf("content-revision-%03d\n", i))
		validHashes[content.SHA256Bytes(contentBytes)] = true
	}

	var withHash, withoutHash int
	for e := range observer.Events() {
		if e.ActionType != models.FileClose || e.Target != target {
			continue
		}
		if e.OutputHash == nil {
			withoutHash++
			continue
		}
		withHash++
		if !validHashes[*e.OutputHash] {
			t.Errorf("FileClose carried a corrupted/TOCTOU OutputHash %q; must be one of the exact revision hashes",
				*e.OutputHash)
		}
	}

	t.Logf("raced-rewrite: %d FileClose with a valid revision hash, %d conservatively without",
		withHash, withoutHash)
	if withHash+withoutHash == 0 {
		t.Skip("no FileClose events observed for the target (kernel merged them); nothing to assert")
	}
}

func TestTier4_E2E_NotFaithful_InputHashSubstitution(t *testing.T) {
	skipUnprivileged(t)

	c := runFileOnly(t)
	if verdict := c.verify(c.tr); verdict.Outcome != verification.OutcomeFaithful {
		logVerdict(t, verdict)
		t.Fatalf("honest content-hashed trajectory was not faithful: %s", verdict.Outcome)
	}

	// simagent's first claim is the open of file1.txt, the file it writes.
	target := c.tr[0].Target
	if filepath.Base(target) != "file1.txt" {
		t.Fatalf("first claim targets %s, want file1.txt", target)
	}
	trajectory := append(models.Trajectory{}, c.tr...)
	mutated := false
	for index := range trajectory {
		entry := &trajectory[index]
		if entry.ActionType != models.FileOpen || entry.Target != target || entry.InputHash == nil {
			continue
		}
		bogusHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		entry.InputHash = &bogusHash
		mutated = true
		break
	}
	if !mutated {
		t.Fatalf("no content-hashed FileOpen entry for %s", target)
	}

	verdict := c.verify(trajectory)
	if verdict.Outcome != verification.OutcomeNotFaithful {
		t.Fatalf("outcome = %s, want NOT FAITHFUL after substituting the InputHash", verdict.Outcome)
	}
	for _, pair := range verdict.Mismatched {
		if pair.Entry.ActionType == models.FileOpen && pair.Entry.Target == target {
			return
		}
	}
	logVerdict(t, verdict)
	t.Fatalf("InputHash substitution for %s was not classified as Mismatched", target)
}
