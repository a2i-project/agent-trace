package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// These tests need root. The ones named TestKernelHash_ need a kernel with
// the file dynptr kfuncs and the BPF LSM active, and skip elsewhere; GitHub's
// runners have no BPF LSM (P-48), so they run on a developer's machine
// through scripts/test-privileged-local.sh (I-129).

// requireKernelHash skips unless the kernel copy can run here.
func requireKernelHash(t *testing.T) {
	t.Helper()
	skipUnprivileged(t)
	if why := kernelHashSupport(); why != "" {
		t.Skip("kernel content copy unavailable: " + why)
	}
}

// startKernelHashObserver starts an observer on dir, filtered to this
// process, with the kernel copy asked for.
func startKernelHashObserver(t *testing.T, dir string, contentCap uint64) *Observer {
	t.Helper()
	obs, err := New(Config{
		Path:          dir,
		PathFilter:    dir,
		PIDFilter:     int32(os.Getpid()),
		EventBufSize:  1024,
		KernelHash:    true,
		KernelHashCap: contentCap,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	return obs
}

// stopForCoverage stops the observer, returns the closes on target in
// order, and its file hash counts.
func stopForCoverage(t *testing.T, obs *Observer, target string) ([]models.GroundTruthEvent, *models.FileHashCounts) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	done := make(chan []models.GroundTruthEvent)
	go func() {
		var closes []models.GroundTruthEvent
		for e := range obs.Events() {
			if e.ActionType == models.FileClose && e.Target == target {
				closes = append(closes, e)
			}
		}
		done <- closes
	}()
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	closes := <-done
	d := obs.CaptureCoverage().Diagnostics
	if d == nil || d.FileHashes == nil {
		t.Fatal("no FileHashes in the coverage record with KernelHash set")
	}
	t.Logf("file hashes: %+v", *d.FileHashes)
	return closes, d.FileHashes
}

func writeAndClose(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestObserver_KernelHashOptionOnEveryKernel runs on every root runner: with
// the option set, a written and closed file is hashed, by the kernel where
// it can run (and then the copy must load: a verifier rejection fails here)
// and by the userspace path elsewhere, with the reason in the coverage
// record.
func TestObserver_KernelHashOptionOnEveryKernel(t *testing.T) {
	skipUnprivileged(t)
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	why := kernelHashSupport()
	t.Logf("kernel %s, kernel copy support: %q", unix.ByteSliceToString(uts.Release[:]), why)

	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")
	obs := startKernelHashObserver(t, dir, 0)
	writeAndClose(t, target, []byte("hello kernel hash\n"))
	closes, counts := stopForCoverage(t, obs, target)

	want := content.SHA256Bytes([]byte("hello kernel hash\n"))
	if len(closes) != 1 || closes[0].OutputHash == nil || *closes[0].OutputHash != want {
		t.Fatalf("closes = %+v, want one with %s", closes, want)
	}
	if why == "" {
		if counts.Mode != khashModeKernel || counts.Kernel < 1 {
			t.Fatalf("counts = %+v, want the kernel copy to run and hash the close", *counts)
		}
		return
	}
	if !strings.HasPrefix(counts.Mode, "unavailable: ") || counts.Kernel != 0 || counts.Userspace < 1 {
		t.Fatalf("counts = %+v, want the userspace path and the reason", *counts)
	}
}

// TestKernelHash_TheWritersReopenKeepsTheHash: the writer reads its file
// back right after closing it, which withdraws a userspace hash (P-39); the
// kernel copy keeps it (P-48).
func TestKernelHash_TheWritersReopenKeepsTheHash(t *testing.T) {
	requireKernelHash(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")
	obs := startKernelHashObserver(t, dir, 0)
	writeAndClose(t, target, []byte("written then read back\n"))
	if _, err := os.ReadFile(target); err != nil {
		t.Fatal(err)
	}
	closes, counts := stopForCoverage(t, obs, target)
	want := content.SHA256Bytes([]byte("written then read back\n"))
	if len(closes) != 1 || closes[0].OutputHash == nil || *closes[0].OutputHash != want {
		t.Fatalf("closes = %+v, want one with %s", closes, want)
	}
	if counts.Kernel < 1 {
		t.Fatalf("counts = %+v, want a kernel hash", *counts)
	}
}

// TestKernelHash_ADeletedFileKeepsItsHash: a file deleted right after its
// close is hashed, from the copy made before the deletion.
func TestKernelHash_ADeletedFileKeepsItsHash(t *testing.T) {
	requireKernelHash(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "tmp.txt")
	obs := startKernelHashObserver(t, dir, 0)
	writeAndClose(t, target, []byte("short-lived\n"))
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	closes, _ := stopForCoverage(t, obs, target)
	want := content.SHA256Bytes([]byte("short-lived\n"))
	if len(closes) != 1 || closes[0].OutputHash == nil || *closes[0].OutputHash != want {
		t.Fatalf("closes = %+v, want one with %s", closes, want)
	}
}

// TestKernelHash_AnotherWriterSendsTheCloseToUserspace: a close while
// another descriptor still holds the file for writing gets no kernel hash
// (writer_held), and the userspace path then declines too, since this
// process still writes (P-26). The last close is the only writer and is
// hashed by the kernel.
func TestKernelHash_AnotherWriterSendsTheCloseToUserspace(t *testing.T) {
	requireKernelHash(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "shared.txt")
	obs := startKernelHashObserver(t, dir, 0)
	first, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.OpenFile(target, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.WriteString("one\n"); err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	time.Sleep(100 * time.Millisecond)
	if _, err := second.WriteAt([]byte("two\n"), 4); err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	closes, counts := stopForCoverage(t, obs, target)
	if counts.Fallbacks["writer_held"] < 1 {
		t.Fatalf("counts = %+v, want a writer_held fallback", *counts)
	}
	last := closes[len(closes)-1]
	want := content.SHA256Bytes([]byte("one\ntwo\n"))
	if last.OutputHash == nil || *last.OutputHash != want {
		t.Fatalf("last close = %+v, want %s", last, want)
	}
}

// TestKernelHash_AFileOverTheCapTakesTheUserspacePath: a file larger than
// the cap is not copied; the userspace path hashes it.
func TestKernelHash_AFileOverTheCapTakesTheUserspacePath(t *testing.T) {
	requireKernelHash(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "big.txt")
	obs := startKernelHashObserver(t, dir, 16)
	data := []byte(strings.Repeat("x", 64))
	writeAndClose(t, target, data)
	closes, counts := stopForCoverage(t, obs, target)
	if counts.Fallbacks["too_large"] < 1 || counts.Kernel != 0 {
		t.Fatalf("counts = %+v, want a too_large fallback", *counts)
	}
	if len(closes) != 1 || closes[0].OutputHash == nil || *closes[0].OutputHash != content.SHA256Bytes(data) {
		t.Fatalf("closes = %+v, want the userspace hash", closes)
	}
}

// TestKernelHash_RapidRewritesHashOnlyWrittenContent rewrites one file 200
// times without pause. Every published hash must be the content of one of
// the rewrites (a merged record takes its process's newest close, P-26,
// P-49), and most closes are hashed by the kernel.
func TestKernelHash_RapidRewritesHashOnlyWrittenContent(t *testing.T) {
	requireKernelHash(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "churn.txt")
	obs := startKernelHashObserver(t, dir, 0)
	written := map[string]bool{}
	for i := 0; i < 200; i++ {
		data := []byte(fmt.Sprintf("rewrite %d %s\n", i, strings.Repeat("y", i)))
		written[content.SHA256Bytes(data)] = true
		writeAndClose(t, target, data)
	}
	closes, counts := stopForCoverage(t, obs, target)
	hashed := 0
	for _, c := range closes {
		if c.OutputHash == nil {
			continue
		}
		hashed++
		if !written[*c.OutputHash] {
			t.Fatalf("close hashed %s, the content of no rewrite", *c.OutputHash)
		}
	}
	t.Logf("%d closes, %d hashed", len(closes), hashed)
	if counts.Kernel == 0 {
		t.Fatalf("counts = %+v, want kernel hashes", *counts)
	}
}
