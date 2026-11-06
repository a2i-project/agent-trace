package verification

import (
	"path/filepath"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// failedAttempts returns the indexes in events, in time order, of the exec
// attempts of a PATH search that failed (I-157): an exec without the
// kernel's record that it took effect (Image) whose process's next event
// is an exec of the same program name with the same arguments from another
// absolute directory, in a run of such execs that ends in one with an
// Image. A PATH lookup tries each directory in turn: Codex starts its
// helper commands this way, and a login shell's systemd-cat runs echo so.
// The Image at the end of the run is what makes the earlier ones failed
// attempts rather than execs whose record was lost; a capture made before
// the probe recorded images (P-36) has none, so nothing in it is one. The
// attempts stay in the stream; the forest does not take one as a process's
// exec, and the partition keeps them apart (Partition.Attempts), so a
// command's exec is the program that ran and its programs run are those
// that took effect.
func failedAttempts(events []models.GroundTruthEvent) map[int]bool {
	next := map[int]int{}
	last := map[uint32]int{}
	for i, e := range events {
		if e.PID == 0 {
			continue
		}
		if j, ok := last[e.PID]; ok {
			next[j] = i
		}
		last[e.PID] = i
	}
	var failed map[int]bool
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.ActionType != models.ProcessExec || e.Image != nil || e.TargetTruncated || e.PID == 0 {
			continue
		}
		j, ok := next[i]
		if !ok {
			continue
		}
		n := events[j]
		if n.ActionType != models.ProcessExec || n.TargetTruncated || !sameSearch(e.Target, n.Target) {
			continue
		}
		if n.Image != nil || failed[j] {
			if failed == nil {
				failed = map[int]bool{}
			}
			failed[i] = true
		}
	}
	return failed
}

// sameSearch reports whether two command lines run the same program name
// from two absolute directories with the same arguments.
func sameSearch(a, b string) bool {
	pa, aa, _ := strings.Cut(a, " ")
	pb, ab, _ := strings.Cut(b, " ")
	return aa == ab && filepath.IsAbs(pa) && filepath.IsAbs(pb) && pa != pb &&
		filepath.Base(pa) == filepath.Base(pb) && filepath.Dir(pa) != filepath.Dir(pb)
}
