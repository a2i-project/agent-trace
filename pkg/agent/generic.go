package agent

import (
	"fmt"
	"os"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// GenericName is the name the generic adapter registers under.
const GenericName = "generic"

// Generic reads a trajectory already in the normalized JSON form, applies no
// normalization and knows no harness noise. It lets an agent whose own format
// has been converted elsewhere verify at reduced precision with no adapter
// written. It never detects a path: it is chosen by name, or by a caller that
// found no other adapter.
type Generic struct{}

func init() { Register(Generic{}) }

func (Generic) Name() string { return GenericName }

func (Generic) Detect(string) bool { return false }

func (Generic) Parse(path string) (models.Trajectory, Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, Report{}, err
	}
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		return nil, Report{}, fmt.Errorf("parse trajectory %s: %w", path, err)
	}
	r := Report{
		ToolCalls: len(tr),
		Entries:   len(tr),
		Degradations: []string{
			"generic adapter: no harness noise filter, no command wrapper recovery, every content field treated as expressible",
		},
	}
	return tr, r, nil
}

func (Generic) Normalize(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) { return e, true }

func (Generic) IsHarnessNoise(models.GroundTruthEvent) bool { return false }

func (Generic) Expresses(models.TrajectoryEntry, string) bool { return true }

func (Generic) Process() ProcessModel {
	return ProcessModel{ShellPerCommand: true, IntervalKind: IntervalNone, Concurrency: Sequential, ExitsClaimed: true}
}
