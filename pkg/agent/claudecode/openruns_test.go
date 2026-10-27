package claudecode

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/agent/gemini"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The claims and NormalizeStream of Claude Code count a run of opens of one
// file as one access, so Prepare asks the verifier to fold a run that only
// set-aside events broke (V-49). agy's claims do not collapse opens (I-50),
// so its adapter does not declare it.
func TestPrepareDeclaresTheCollapseOfOpenRuns(t *testing.T) {
	if in := agent.Prepare(Adapter{}, nil, models.GroundTruthFile{}, nil, verification.Options{}); !in.Options.CollapseOpenRuns {
		t.Error("claude-code: CollapseOpenRuns not set")
	}
	if in := agent.Prepare(gemini.Adapter{}, nil, models.GroundTruthFile{}, nil, verification.Options{}); in.Options.CollapseOpenRuns {
		t.Error("gemini: CollapseOpenRuns set")
	}
}
