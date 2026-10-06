package matching

import (
	"path/filepath"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

const DefaultDelta = 1 * time.Second

type Config struct {
	Delta time.Duration
}

func DefaultConfig() Config {
	return Config{Delta: DefaultDelta}
}

func isFileAction(actionType models.ActionType) bool {
	switch actionType {
	case models.FileOpen, models.FileRead, models.FileWrite,
		models.FileClose, models.FileRename, models.FileDelete:
		return true
	default:
		return false
	}
}

// targetsMatch reports whether a trajectory target and a ground-truth target
// refer to the same resource, applying per-action-type normalization.
// gPathIsAmbiguous mirrors the ground-truth event's PathIsAmbiguous field
// (see models.GroundTruthEvent) and gates the directory-covers-file fallback
// below.
func targetsMatch(actionType models.ActionType, tTarget, gTarget string, gPathIsAmbiguous bool) bool {
	switch {
	case isFileAction(actionType):
		normT := filepath.Clean(tTarget)
		normG := filepath.Clean(gTarget)
		if normT == normG {
			return true
		}
		// A directory-level ground-truth event (fanotify merged events and
		// dropped the filename, leaving only a DFID record) corroborates a
		// file operation that happened inside it. This leniency only
		// applies when the ground truth is genuinely a coarse-resolution
		// record; an exactly-resolved ground-truth path that merely happens
		// to equal a directory must match exactly, or a single ground-truth
		// event could be stretched to corroborate any filename in that
		// directory.
		return gPathIsAmbiguous && normG == filepath.Dir(normT)
	default:
		// Strict equality for all other action types, including ProcessExec and ProcessExit.
		return tTarget == gTarget
	}
}

// TargetsMatch reports whether a claim and an observed event name the same
// resource, applying the per-action-type normalization of targetsMatch. It
// is the target half of Match with no timestamp condition and no requirement
// that the two share an action type, so the verifier can pair by position and
// then ask whether the targets agree (08 V4).
func TargetsMatch(t models.TrajectoryEntry, g models.GroundTruthEvent) bool {
	return targetsMatch(t.ActionType, t.Target, g.Target, g.PathIsAmbiguous)
}

// Match reports whether a trajectory entry and a ground-truth event refer to
// the same action: same action_type, same normalized target, and timestamps
// within delta of each other.
func Match(t models.TrajectoryEntry, g models.GroundTruthEvent, cfg Config) bool {
	if t.ActionType != g.ActionType {
		return false
	}

	if !targetsMatch(t.ActionType, t.Target, g.Target, g.PathIsAmbiguous) {
		return false
	}

	diff := t.Timestamp.Sub(g.Timestamp)
	if diff < 0 {
		diff = -diff
	}
	return diff <= cfg.Delta
}
