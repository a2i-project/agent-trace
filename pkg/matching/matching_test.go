package matching

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

var baseTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func entry(offset time.Duration, action models.ActionType, target string) models.TrajectoryEntry {
	return models.TrajectoryEntry{
		Timestamp:  baseTime.Add(offset),
		ActionType: action,
		Target:     target,
	}
}

func event(offset time.Duration, action models.ActionType, target string) models.GroundTruthEvent {
	return models.GroundTruthEvent{
		Timestamp:  baseTime.Add(offset),
		ActionType: action,
		Target:     target,
	}
}

// ambiguousEvent is like event but sets PathIsAmbiguous, marking Target as a
// directory-only resolution (see resolveEventPath's DFID-only fallback).
func ambiguousEvent(offset time.Duration, action models.ActionType, target string) models.GroundTruthEvent {
	e := event(offset, action, target)
	e.PathIsAmbiguous = true
	return e
}

func TestTargetsMatchExact(t *testing.T) {
	te := entry(0, models.FileWrite, "/tmp/test.txt")
	ge := event(0, models.FileWrite, "/tmp/test.txt")

	if !TargetsMatch(te, ge) {
		t.Error("identical entries should match")
	}
}

// Pairing is by position and the action type is a separate comparison, so a
// claim and an event of different types still agree on a shared target. The
// verifier reports the type difference itself (verification.DiffType).
func TestTargetsMatchIgnoresActionTypeOfTheEvent(t *testing.T) {
	te := entry(0, models.FileWrite, "/tmp/test.txt")
	ge := event(0, models.FileRead, "/tmp/test.txt")

	if !TargetsMatch(te, ge) {
		t.Error("the same file under two action types should agree on the target")
	}
}

// Time plays no part: a constant clock offset between the trajectory and the
// probes must not change whether two targets agree (V6).
func TestTargetsMatchIgnoresTime(t *testing.T) {
	te := entry(0, models.FileWrite, "/tmp/test.txt")
	ge := event(48*time.Hour, models.FileWrite, "/tmp/test.txt")

	if !TargetsMatch(te, ge) {
		t.Error("a timestamp 48 hours apart changed the target comparison")
	}
}

func TestNoMatchDifferentTarget(t *testing.T) {
	te := entry(0, models.FileWrite, "/tmp/a.txt")
	ge := event(0, models.FileWrite, "/tmp/b.txt")

	if TargetsMatch(te, ge) {
		t.Error("different targets should not match")
	}
}

func TestFilePathNormalization(t *testing.T) {

	tests := []struct {
		name    string
		tTarget string
		gTarget string
		want    bool
	}{
		{
			name:    "dot segment removed",
			tTarget: "/workspace/./src/main.go",
			gTarget: "/workspace/src/main.go",
			want:    true,
		},
		{
			name:    "double dot resolved",
			tTarget: "/workspace/src/../src/main.go",
			gTarget: "/workspace/src/main.go",
			want:    true,
		},
		{
			name:    "trailing slash removed",
			tTarget: "/workspace/src/",
			gTarget: "/workspace/src",
			want:    true,
		},
		{
			name:    "genuinely different paths",
			tTarget: "/workspace/src/main.go",
			gTarget: "/workspace/src/lib.go",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			te := entry(0, models.FileWrite, tc.tTarget)
			ge := event(0, models.FileWrite, tc.gTarget)
			got := TargetsMatch(te, ge)
			if got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.tTarget, tc.gTarget, got, tc.want)
			}
		})
	}
}

// TestDirectoryFallbackRequiresAmbiguousFlag pins Fix 6: the directory-
// covers-file leniency in targetsMatch must only apply when the ground
// truth is a genuinely ambiguous (kernel-merged, DFID-only) record. Before
// this fix, any ground-truth event whose Target happened to equal a
// directory could corroborate any filename inside it.
func TestDirectoryFallbackRequiresAmbiguousFlag(t *testing.T) {
	te := entry(0, models.FileWrite, "/workspace/src/main.go")

	t.Run("ambiguous directory-only ground truth still matches", func(t *testing.T) {
		ge := ambiguousEvent(0, models.FileWrite, "/workspace/src")
		if !TargetsMatch(te, ge) {
			t.Error("an ambiguous directory-level ground truth should corroborate a file inside it")
		}
	})

	t.Run("exactly-resolved directory target does not match", func(t *testing.T) {
		ge := event(0, models.FileWrite, "/workspace/src")
		if TargetsMatch(te, ge) {
			t.Error("a non-ambiguous ground-truth event equal to a directory must not corroborate an unrelated file inside it")
		}
	})
}

func TestProcessCommandStrictMatching(t *testing.T) {

	tests := []struct {
		name    string
		tTarget string
		gTarget string
		want    bool
	}{
		{
			name:    "identical bare names",
			tTarget: "ls",
			gTarget: "ls",
			want:    true,
		},
		{
			name:    "identical absolute paths",
			tTarget: "/usr/bin/ls -la",
			gTarget: "/usr/bin/ls -la",
			want:    true,
		},
		{
			name:    "bare name vs absolute path should NOT match",
			tTarget: "ls",
			gTarget: "/usr/bin/ls",
			want:    false,
		},
		{
			name:    "same arguments but bare vs absolute should NOT match",
			tTarget: "wc -l /tmp/test",
			gTarget: "/usr/bin/wc -l /tmp/test",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			te := entry(0, models.ProcessExec, tc.tTarget)
			ge := event(0, models.ProcessExec, tc.gTarget)
			got := TargetsMatch(te, ge)
			if got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.tTarget, tc.gTarget, got, tc.want)
			}
		})
	}
}

func TestNoNormalizationForNonFileActions(t *testing.T) {
	te := entry(0, models.NetRequest, "https://api.example.com/v1/chat")
	ge := event(0, models.NetRequest, "https://api.example.com/v1/chat")

	if !TargetsMatch(te, ge) {
		t.Error("identical net targets should match")
	}

	te2 := entry(0, models.NetRequest, "https://api.example.com/v1/chat")
	ge2 := event(0, models.NetRequest, "https://api.example.com/v1/Chat")

	if TargetsMatch(te2, ge2) {
		t.Error("net targets are case-sensitive, should not match")
	}
}
