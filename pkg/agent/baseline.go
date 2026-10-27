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
// directory with every character but an ASCII letter or digit replaced by a
// dash, which is how Claude Code names the per-project directories that hold
// its transcripts, task outputs and logs (I-70).
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
	// Subtrees records, for every command rule (a process_exec rule), what
	// the command did beneath it in the control runs: the programs run, files
	// written, renamed or deleted, connections and requests
	// (verification.SubtreeChecked), as rules of the same form, kept at the
	// same agreement threshold. It records the same for each declared
	// harness command that some control ran and that is not a rule, counted
	// over the controls that ran it (Subtree.Declared, V-43). In a run, a baselined command explains only
	// the events beneath it that its record holds (V-38). Nil, as in a
	// baseline written before V-38, records nothing and leaves every
	// baselined command explaining its whole subtree (V7); Capture always
	// sets it, empty when there is no command rule.
	Subtrees []Subtree `json:"subtrees"`
	// Sensitive is what the controls changed in the harness's declared
	// security-sensitive files between the start and the stop of each run
	// (V-40). Nil, as in a baseline written before V-40 or built from
	// controls without a snapshot, records nothing, and verify then checks
	// no change of those files.
	Sensitive *SensitiveBaseline `json:"sensitive,omitempty"`
}

// SensitiveBaseline is what the controls changed in the harness's
// security-sensitive files (V-40).
type SensitiveBaseline struct {
	// Files are the declared files every control measured at both ends; a
	// change of another file is not checked.
	Files []string `json:"files"`
	// Changes are the changes enough controls made; they are explained in a
	// run.
	Changes []SensitiveRule `json:"changes"`
	// Unstable lists the changes made by at least one control but too few.
	// Recorded for the reader; they explain nothing.
	Unstable []SensitiveRule `json:"unstable,omitempty"`
}

// SensitiveRule is one change of a sensitive file: the file as the adapter
// declares it, the key path with the run's workspace replaced by the
// placeholder, and the kind of change. No value: the snapshot records none.
type SensitiveRule struct {
	File string   `json:"file"`
	Key  []string `json:"key,omitempty"`
	Kind string   `json:"kind"`
}

// Subtree is what one command rule's command did beneath it in the control
// runs (V-38).
type Subtree struct {
	// Command is the target of the process_exec rule.
	Command string `json:"command"`
	// Events are the actions enough control runs' same command performed
	// beneath it; they are explained beneath it in a run.
	Events []Rule `json:"events"`
	// Unstable lists the actions seen beneath the command in at least one
	// control run but too few of them. Recorded for the reader; they explain
	// nothing.
	Unstable []Rule `json:"unstable,omitempty"`
	// Declared marks the record of a command the adapter declares as the
	// harness's own (HarnessCommander) that is not a command rule at this
	// agreement: its actions are counted over the controls that ran it, and
	// it explains nothing beneath a command no rule matches except under
	// that declaration (V-43).
	Declared bool `json:"declared,omitempty"`
}

// RecordsSubtrees reports whether the baseline holds the subtrees of its
// commands (V-38). A baseline written before V-38 does not.
func (b Baseline) RecordsSubtrees() bool { return b.Subtrees != nil }

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
// are not rules; what they did is recorded per command rule in Subtrees, so a
// baselined command explains only what its controls did beneath it (V-38). A
// run with no root pid cannot be attributed and is an error.
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
	// subCounts[command][rule] counts the runs in which some instance of the
	// command did rule beneath it.
	subCounts := map[string]map[Rule]int{}
	// declaredRuns[command] counts the runs in which a declared harness
	// command ran, as HarnessCommand recognises it (V-43).
	declaredRuns := map[string]int{}
	for i, r := range runs {
		if r.RootPID == 0 {
			return Baseline{}, fmt.Errorf("control run %d has no root pid, so its events cannot be attributed", i+1)
		}
		g := NormalizeGround(a, r.Events)
		part := verification.BuildForest(g, r.RootPID).Partition(g)
		seen := map[Rule]bool{}
		for _, e := range part.Observed {
			// A rule is compared with other runs, so it names the event in
			// its canonical form (I-41).
			e = canonical(a, e)
			if excluded[e.Target] {
				continue
			}
			seen[Rule{ActionType: e.ActionType, Target: templateWorkspace(e.Target, r.Workspace)}] = true
		}
		for rule := range seen {
			counts[rule]++
		}
		// What each command did beneath it, in the same canonical form.
		seenSub := map[string]map[Rule]bool{}
		declared := HarnessCommand(a, r.Events)
		seenDeclared := map[string]bool{}
		for _, c := range part.Commands {
			if c.Exec == nil {
				continue
			}
			ce := canonical(a, *c.Exec)
			if excluded[ce.Target] {
				continue
			}
			cmd := templateWorkspace(ce.Target, r.Workspace)
			if declared != nil && declared(*c.Exec) {
				seenDeclared[cmd] = true
			}
			if seenSub[cmd] == nil {
				seenSub[cmd] = map[Rule]bool{}
			}
			for _, e := range c.Content {
				if !verification.SubtreeChecked(e.ActionType) {
					continue
				}
				e = canonical(a, e)
				seenSub[cmd][Rule{ActionType: e.ActionType, Target: templateWorkspace(e.Target, r.Workspace)}] = true
			}
		}
		for cmd := range seenDeclared {
			declaredRuns[cmd]++
		}
		for cmd, rules := range seenSub {
			if subCounts[cmd] == nil {
				subCounts[cmd] = map[Rule]int{}
			}
			for rule := range rules {
				subCounts[cmd][rule]++
			}
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
	b.Subtrees = []Subtree{}
	for _, rule := range b.Rules {
		if rule.ActionType != models.ProcessExec {
			continue
		}
		st := Subtree{Command: rule.Target, Events: []Rule{}}
		for sub, n := range subCounts[rule.Target] {
			if n >= need {
				st.Events = append(st.Events, sub)
			} else {
				st.Unstable = append(st.Unstable, sub)
			}
		}
		sortRules(st.Events)
		sortRules(st.Unstable)
		b.Subtrees = append(b.Subtrees, st)
	}
	b.Subtrees = append(b.Subtrees, declaredSubtrees(b.Rules, declaredRuns, subCounts, agreement)...)
	b.Sensitive = captureSensitive(a, runs, need)
	return b, nil
}

// declaredSubtrees records what each declared harness command that is not a
// command rule did beneath it in the controls that ran it (V-43): an action
// is kept when at least the agreement's share of those controls did it
// beneath the command, at least one, and is unstable otherwise. A declared
// command that is a rule has its record among the rules' (V-38); one no
// control ran has no record, so in a run everything checked beneath it is
// unexplained.
func declaredSubtrees(rules []Rule, runs map[string]int, subCounts map[string]map[Rule]int, agreement float64) []Subtree {
	isRule := map[string]bool{}
	for _, r := range rules {
		if r.ActionType == models.ProcessExec {
			isRule[r.Target] = true
		}
	}
	cmds := make([]string, 0, len(runs))
	for cmd := range runs {
		if !isRule[cmd] {
			cmds = append(cmds, cmd)
		}
	}
	sort.Strings(cmds)
	var out []Subtree
	for _, cmd := range cmds {
		need := int(math.Ceil(agreement*float64(runs[cmd]) - 1e-9))
		if need < 1 {
			need = 1
		}
		st := Subtree{Command: cmd, Declared: true, Events: []Rule{}}
		for sub, n := range subCounts[cmd] {
			if n >= need {
				st.Events = append(st.Events, sub)
			} else {
				st.Unstable = append(st.Unstable, sub)
			}
		}
		sortRules(st.Events)
		sortRules(st.Unstable)
		out = append(out, st)
	}
	return out
}

// captureSensitive is what the controls changed in the adapter's declared
// sensitive files, at the agreement rules use (V-40). Nil when the adapter
// declares no file or some control has no snapshot: a record built from part
// of the controls would read the rest as having changed nothing.
func captureSensitive(a Adapter, runs []models.GroundTruthFile, need int) *SensitiveBaseline {
	declared := SensitiveFiles(a)
	if len(declared) == 0 {
		return nil
	}
	for _, r := range runs {
		if r.Sensitive == nil {
			return nil
		}
	}
	sb := &SensitiveBaseline{Files: []string{}, Changes: []SensitiveRule{}}
	for _, d := range declared {
		measured := true
		for _, r := range runs {
			f := snapshotFile(r.Sensitive, d)
			if f == nil || !f.Start.Measured() || !f.Stop.Measured() {
				measured = false
				break
			}
		}
		if measured {
			sb.Files = append(sb.Files, d)
		}
	}
	counts := map[string]int{}
	rules := map[string]SensitiveRule{}
	for _, r := range runs {
		seen := map[string]bool{}
		for _, d := range sb.Files {
			for _, c := range snapshotFile(r.Sensitive, d).Changes {
				rule := SensitiveRule{File: d, Key: templateKey(c.Key, r.Workspace), Kind: c.Kind}
				id := rule.id()
				rules[id] = rule
				seen[id] = true
			}
		}
		for id := range seen {
			counts[id]++
		}
	}
	for id, n := range counts {
		if n >= need {
			sb.Changes = append(sb.Changes, rules[id])
		} else {
			sb.Unstable = append(sb.Unstable, rules[id])
		}
	}
	sortSensitive(sb.Changes)
	sortSensitive(sb.Unstable)
	return sb
}

// snapshotFile is the snapshot's entry for a declared file, or nil.
func snapshotFile(s *models.SensitiveSnapshot, declared string) *models.SensitiveFile {
	if s == nil {
		return nil
	}
	for i := range s.Files {
		if s.Files[i].Declared == declared {
			return &s.Files[i]
		}
	}
	return nil
}

// templateKey is a key path with the run's workspace replaced by the
// placeholder in every element, as rules name it (I-24): Claude Code keys
// its per-project entries of ~/.claude.json by the directory.
func templateKey(key []string, workspace string) []string {
	if len(key) == 0 {
		return nil
	}
	out := make([]string, len(key))
	for i, k := range key {
		out[i] = templateWorkspace(k, workspace)
	}
	return out
}

// id is the rule as one comparable string.
func (r SensitiveRule) id() string {
	k, _ := json.Marshal(r.Key)
	return r.File + "\x00" + string(k) + "\x00" + r.Kind
}

func sortSensitive(r []SensitiveRule) {
	sort.Slice(r, func(i, j int) bool { return r[i].id() < r[j].id() })
}

// SensitiveExplained returns the baseline's sensitive record for a run that
// watched workspace, as the verifier asks it: did the controls make this
// change. The run's key is compared with the workspace replaced by the
// placeholder, exactly; there is no other pattern. Nil when the baseline
// records no sensitive changes.
func (b Baseline) SensitiveExplained(workspace string) func(verification.SensitiveChange) bool {
	if b.Sensitive == nil {
		return nil
	}
	set := make(map[string]bool, len(b.Sensitive.Changes))
	for _, r := range b.Sensitive.Changes {
		set[r.id()] = true
	}
	return func(c verification.SensitiveChange) bool {
		return set[SensitiveRule{File: c.File, Key: templateKey(c.Key, workspace), Kind: c.Kind}.id()]
	}
}

// templateWorkspace replaces the watched directory inside a target with the
// placeholder. A workspace that is empty or the root is left alone: replacing
// "/" would rewrite every path.
func templateWorkspace(target, workspace string) string {
	if len(workspace) < 2 {
		return target
	}
	target = strings.ReplaceAll(target, workspace, WorkspacePlaceholder)
	if m, ok := mangle(workspace); ok {
		target = strings.ReplaceAll(target, m, MangledWorkspacePlaceholder)
	}
	return target
}

// maxMangled is the longest directory name Claude Code derives from a path
// as it is; a longer one it cuts and suffixes with a hash of the path.
const maxMangled = 200

// mangle is the workspace as Claude Code spells it in a directory name
// (I-70): every UTF-16 code unit that is not an ASCII letter or digit
// becomes a dash, as its replace(/[^a-zA-Z0-9]/g, "-") does. ok is false
// for a name longer than maxMangled, which the harness shortens with a hash
// this package does not compute.
func mangle(workspace string) (string, bool) {
	var b strings.Builder
	n := 0
	for _, r := range workspace {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			n++
		case r > 0xffff:
			b.WriteString("--")
			n += 2
		default:
			b.WriteByte('-')
			n++
		}
	}
	return b.String(), n <= maxMangled
}

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
		var ok bool
		if r.Target, ok = expandWorkspace(r.Target, workspace); ok {
			set[r] = true
		}
	}
	return func(e models.GroundTruthEvent) bool {
		return set[Rule{ActionType: e.ActionType, Target: e.Target}]
	}
}

// expandWorkspace puts the workspace in place of the placeholders of a
// target. It reports false for a target that names a placeholder when the run
// has no workspace: such a rule matches nothing.
func expandWorkspace(target, workspace string) (string, bool) {
	if !strings.Contains(target, WorkspacePlaceholder) && !strings.Contains(target, MangledWorkspacePlaceholder) {
		return target, true
	}
	if len(workspace) < 2 {
		return "", false
	}
	target = strings.ReplaceAll(target, WorkspacePlaceholder, workspace)
	if !strings.Contains(target, MangledWorkspacePlaceholder) {
		return target, true
	}
	m, ok := mangle(workspace)
	if !ok {
		return "", false
	}
	return strings.ReplaceAll(target, MangledWorkspacePlaceholder, m), true
}

// Subtree returns what the baseline's commands did beneath them in the
// controls, for a run that watched workspace, as the verifier asks it: does
// the command whose exec has this target hold this event in its record. The
// events are compared exactly, placeholders expanded, as in Predicate. A
// command with no record explains nothing beneath it. Nil when the baseline
// records no subtrees, which keeps the V7 reading (V-38). The events it is
// asked about must be in their canonical form; BaselineSubtree does that.
func (b Baseline) Subtree(workspace string) verification.SubtreeBaseline {
	if !b.RecordsSubtrees() {
		return nil
	}
	records := map[string]map[Rule]bool{}
	for _, st := range b.Subtrees {
		cmd, ok := expandWorkspace(st.Command, workspace)
		if !ok {
			continue
		}
		set := records[cmd]
		if set == nil {
			set = map[Rule]bool{}
			records[cmd] = set
		}
		for _, r := range st.Events {
			if r.Target, ok = expandWorkspace(r.Target, workspace); ok {
				set[r] = true
			}
		}
	}
	return func(command, e models.GroundTruthEvent) bool {
		return records[command.Target][Rule{ActionType: e.ActionType, Target: e.Target}]
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
