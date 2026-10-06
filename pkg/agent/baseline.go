package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// BaselineSchema is the version of the baseline file this build writes and
// reads.
const BaselineSchema = 1

// Rule is one thing the harness does on its own: an action type and the target
// it acts on, after the adapter's normalization.
type Rule struct {
	ActionType models.ActionType `json:"action_type"`
	Target     string            `json:"target"`
}

// Baseline is the harness's own activity, measured by control runs: the agent
// is given a task that claims nothing, so everything it does is by construction
// the harness (07 D11, 08 V7). It is keyed on the agent and its version, since
// a harness's activity changes between versions.
type Baseline struct {
	Schema       int       `json:"schema"`
	Agent        string    `json:"agent"`
	AgentVersion string    `json:"agent_version"`
	Captured     time.Time `json:"captured"`
	// Runs is how many control runs the rules were taken from.
	Runs int `json:"runs"`
	// Rules are the actions every control run performed. Only these subtract
	// anything: an action seen in some runs and not others is not something the
	// harness reliably does.
	Rules []Rule `json:"rules"`
	// Unstable lists the actions seen in at least one control run but not in
	// all of them. They are recorded so the person reading the baseline can see
	// what was left out, and they subtract nothing.
	Unstable []Rule `json:"unstable,omitempty"`
}

// Capture builds a baseline from control runs. Each run's ground truth is
// normalized by the adapter, attributed with the process forest, and reduced to
// the agent's own top-level actions and the commands it started: the
// activity a trajectory would otherwise have to claim. Descendants of a command
// are not rules, since a command's whole subtree is explained once the command
// is. A run with no root pid cannot be attributed and is an error.
func Capture(a Adapter, version string, runs []models.GroundTruthFile, now time.Time) (Baseline, error) {
	if len(runs) == 0 {
		return Baseline{}, fmt.Errorf("a baseline needs at least one control run")
	}
	counts := map[Rule]int{}
	for i, r := range runs {
		if r.RootPID == 0 {
			return Baseline{}, fmt.Errorf("control run %d has no root pid, so its events cannot be attributed", i+1)
		}
		g := make(models.GroundTruth, 0, len(r.Events))
		for _, e := range r.Events {
			if n, keep := a.Normalize(e); keep {
				g = append(g, n)
			}
		}
		seen := map[Rule]bool{}
		for _, e := range verification.BuildForest(g, r.RootPID).Partition(g).Observed {
			seen[Rule{ActionType: e.ActionType, Target: e.Target}] = true
		}
		for rule := range seen {
			counts[rule]++
		}
	}
	b := Baseline{Schema: BaselineSchema, Agent: a.Name(), AgentVersion: version, Captured: now.UTC(), Runs: len(runs)}
	for rule, n := range counts {
		if n == len(runs) {
			b.Rules = append(b.Rules, rule)
		} else {
			b.Unstable = append(b.Unstable, rule)
		}
	}
	sortRules(b.Rules)
	sortRules(b.Unstable)
	return b, nil
}

func sortRules(r []Rule) {
	sort.Slice(r, func(i, j int) bool {
		if r[i].ActionType != r[j].ActionType {
			return r[i].ActionType < r[j].ActionType
		}
		return r[i].Target < r[j].Target
	})
}

// Predicate returns the baseline as a verification baseline. An event is
// explained when a rule has its action type and target exactly. There is no
// pattern matching: a wildcard would explain whatever an attacker made it
// match.
func (b Baseline) Predicate() verification.Baseline {
	set := make(map[Rule]bool, len(b.Rules))
	for _, r := range b.Rules {
		set[r] = true
	}
	return func(e models.GroundTruthEvent) bool {
		return set[Rule{ActionType: e.ActionType, Target: e.Target}]
	}
}

// SaveBaseline writes a baseline as JSON.
func SaveBaseline(path string, b Baseline) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// LoadBaseline reads a baseline and rejects a schema this build does not know.
func LoadBaseline(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return Baseline{}, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if b.Schema != BaselineSchema {
		return Baseline{}, fmt.Errorf("baseline %s has schema %d, this build reads %d", path, b.Schema, BaselineSchema)
	}
	if b.Agent == "" {
		return Baseline{}, fmt.Errorf("baseline %s names no agent", path)
	}
	return b, nil
}
