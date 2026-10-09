package agent

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// BaselineSchema is the version of the baseline file this build writes and
// reads.
const BaselineSchema = 1

// WorkspacePlaceholder stands for the watched directory inside a rule's target,
// so a baseline measured in one directory applies to a run in another. The
// harness inspects the working directory (a git status, a file listing), and
// those commands name it. MangledWorkspacePlaceholder stands for the same
// directory with every slash replaced by a dash, which is how Claude Code
// names the per-project directory that holds its transcripts.
const (
	WorkspacePlaceholder        = "{workspace}"
	MangledWorkspacePlaceholder = "{workspace-}"
)

// Rule is one thing the harness does on its own: an action type and the target
// it acts on, after the adapter's normalization.
type Rule struct {
	ActionType models.ActionType `json:"action_type"`
	Target     string            `json:"target"`
}

// Baseline is the harness's own activity, measured by control runs: the agent
// is given a task that claims nothing, so everything it does is by construction
// the harness (D11, V7). It is keyed on the agent and its version, since
// a harness's activity changes between versions.
type Baseline struct {
	Schema       int       `json:"schema"`
	Agent        string    `json:"agent"`
	AgentVersion string    `json:"agent_version"`
	Captured     time.Time `json:"captured"`
	// Runs is how many control runs the rules were taken from.
	Runs int `json:"runs"`
	// MinAgreement is the fraction of runs that had to perform an action for it
	// to become a rule. One means every run.
	MinAgreement float64 `json:"min_agreement"`
	// Rules are the actions enough control runs performed. Only these subtract
	// anything: an action seen in few runs is not something the harness
	// reliably does.
	Rules []Rule `json:"rules"`
	// Unstable lists the actions seen in at least one control run but too few of
	// them. They are recorded so the person reading the baseline can see what
	// was left out, and they subtract nothing.
	Unstable []Rule `json:"unstable,omitempty"`
	// Excluded lists the targets the caller kept out of the rules: the control
	// task's own command, which the agent was told to run and which is not the
	// harness's activity. A rule for it would explain any later command with
	// that target and its whole subtree without a claim (I-28). Recorded so the
	// reader can see what was left out.
	Excluded []string `json:"excluded,omitempty"`
}

// CaptureOptions tunes Capture.
type CaptureOptions struct {
	// MinAgreement is the fraction of runs that must perform an action for it
	// to become a rule. Zero means one: every run.
	MinAgreement float64
	// Exclude lists targets that never become a rule or an unstable entry,
	// whatever their action type: the command the control task itself was
	// told to run. Matched exactly against the normalized target.
	Exclude []string
}

// Capture builds a baseline from control runs. Each run's ground truth is
// normalized by the adapter, attributed with the process forest, and reduced to
// the agent's own top-level actions and the commands it started: the
// activity a trajectory would otherwise have to claim. Descendants of a command
// are not rules, since a command's whole subtree is explained once the command
// is. A run with no root pid cannot be attributed and is an error.
//
// A harness does some things only some of the time (probing for a package
// manager, say), so the agreement threshold decides how often an action must
// recur to count as the harness's. At one, an occasional action is left out and
// can then read as unexplained in a later run. Below one, a rule can explain an
// action the harness took in only some controls, which is a wider baseline.
func Capture(a Adapter, version string, runs []models.GroundTruthFile, now time.Time, opts CaptureOptions) (Baseline, error) {
	if len(runs) == 0 {
		return Baseline{}, fmt.Errorf("a baseline needs at least one control run")
	}
	agreement := opts.MinAgreement
	if agreement == 0 {
		agreement = 1
	}
	if agreement < 0 || agreement > 1 {
		return Baseline{}, fmt.Errorf("min agreement %v is not a fraction between 0 and 1", agreement)
	}
	need := int(math.Ceil(agreement*float64(len(runs)) - 1e-9))
	if need < 1 {
		need = 1
	}
	excluded := make(map[string]bool, len(opts.Exclude))
	for _, t := range opts.Exclude {
		excluded[t] = true
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
			if excluded[e.Target] {
				continue
			}
			seen[Rule{ActionType: e.ActionType, Target: templateWorkspace(e.Target, r.Workspace)}] = true
		}
		for rule := range seen {
			counts[rule]++
		}
	}
	b := Baseline{Schema: BaselineSchema, Agent: a.Name(), AgentVersion: version, Captured: now.UTC(), Runs: len(runs), MinAgreement: agreement}
	b.Excluded = append(b.Excluded, opts.Exclude...)
	sort.Strings(b.Excluded)
	for rule, n := range counts {
		if n >= need {
			b.Rules = append(b.Rules, rule)
		} else {
			b.Unstable = append(b.Unstable, rule)
		}
	}
	sortRules(b.Rules)
	sortRules(b.Unstable)
	return b, nil
}

// templateWorkspace replaces the watched directory inside a target with the
// placeholder. A workspace that is empty or the root is left alone: replacing
// "/" would rewrite every path.
func templateWorkspace(target, workspace string) string {
	if len(workspace) < 2 {
		return target
	}
	target = strings.ReplaceAll(target, workspace, WorkspacePlaceholder)
	return strings.ReplaceAll(target, mangle(workspace), MangledWorkspacePlaceholder)
}

// mangle is the workspace as Claude Code spells it in a directory name.
func mangle(workspace string) string { return strings.ReplaceAll(workspace, "/", "-") }

func sortRules(r []Rule) {
	sort.Slice(r, func(i, j int) bool {
		if r[i].ActionType != r[j].ActionType {
			return r[i].ActionType < r[j].ActionType
		}
		return r[i].Target < r[j].Target
	})
}

// Predicate returns the baseline as a verification baseline for a run that
// watched workspace. An event is explained when a rule has its action type and
// target exactly, with the placeholder standing for the workspace. There is no
// other pattern matching: a wildcard would explain whatever an attacker made it
// match. With no workspace, a rule that names the placeholder matches nothing.
func (b Baseline) Predicate(workspace string) verification.Baseline {
	set := make(map[Rule]bool, len(b.Rules))
	for _, r := range b.Rules {
		if strings.Contains(r.Target, WorkspacePlaceholder) || strings.Contains(r.Target, MangledWorkspacePlaceholder) {
			if len(workspace) < 2 {
				continue
			}
			r.Target = strings.ReplaceAll(r.Target, WorkspacePlaceholder, workspace)
			r.Target = strings.ReplaceAll(r.Target, MangledWorkspacePlaceholder, mangle(workspace))
		}
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
