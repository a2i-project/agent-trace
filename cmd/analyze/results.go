package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/config"
)

// Options are the command's inputs.
type Options struct {
	Campaign string
	Out      string
	Config   string
	// Comparison is the output directory of scripts/compare/sweep.py (H1).
	Comparison string
	// Overhead and OverheadAfter are labelled benchmark results.json files
	// (label=path); a label in both gives the machine drift between them.
	Overhead      []string
	OverheadAfter []string
	// LastSeed bounds the attack sweep's seeds; Registered is SeedLast.
	LastSeed uint64
	Jobs     int
	// NoSweep, NoSensitivity and NoLOO skip the costly parts; a skipped
	// part is listed under what was not computed.
	NoSweep       bool
	NoSensitivity bool
	NoLOO         bool
	Diagnostics   string
	MeasureCost   string
}

// Inputs records what the numbers were computed from.
type Inputs struct {
	Campaign       string `json:"campaign_directory"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ManifestCommit string `json:"manifest_commit"`
	ManifestStamp  string `json:"manifest_generated"`
	Annotations    bool   `json:"annotations_file"`
	// Paths are recorded by their last element only, and the agent config
	// by its content hash beside its name, so results.json carries no path
	// of the analysing machine.
	AgentConfig       string   `json:"agent_config,omitempty"`
	AgentConfigSHA256 string   `json:"agent_config_sha256,omitempty"`
	Comparison        string   `json:"comparison_directory,omitempty"`
	Overhead          []string `json:"overhead_runs,omitempty"`
}

// Constants snapshots the registered values the run used, so the results
// carry the registration they were computed under.
type Constants struct {
	Protocol           string      `json:"protocol"`
	BootstrapResamples int         `json:"bootstrap_resamples"`
	BootstrapSeed      uint64      `json:"bootstrap_seed"`
	PrimaryAgreement   float64     `json:"primary_agreement"`
	AgreementGrid      []Agreement `json:"agreement_grid"`
	SeedFirst          uint64      `json:"seed_first"`
	SeedLast           uint64      `json:"seed_last_registered"`
	SeedLastRun        uint64      `json:"seed_last_run"`
	NearZeroFP         float64     `json:"h3a_near_zero"`
	ClaudeFaithfulBar  float64     `json:"h3d_claude_code_bar"`
	MaxWallRatio       float64     `json:"h4a_max_wall_ratio"`
	MaxFixedCostS      float64     `json:"h4a_max_fixed_cost_s"`
	MaxWatchRSSMiB     float64     `json:"h4a_max_watch_rss_mib"`
	MaxLossRuns        int         `json:"h4a_max_loss_runs"`
	IntervalSlackMS    int64       `json:"interval_slack_ms"`
	CauseOrder         []string    `json:"inconclusive_cause_precedence"`
}

func constants(lastSeed uint64) Constants {
	return Constants{
		Protocol: Protocol, BootstrapResamples: BootstrapResamples, BootstrapSeed: BootstrapSeed,
		PrimaryAgreement: PrimaryAgreement, AgreementGrid: AgreementGrid, SeedFirst: SeedFirst, SeedLast: SeedLast, SeedLastRun: lastSeed,
		NearZeroFP: NearZeroFP, ClaudeFaithfulBar: ClaudeFaithfulBar, MaxWallRatio: MaxWallRatio, MaxFixedCostS: MaxFixedCostSeconds,
		MaxWatchRSSMiB: MaxWatchRSSMiB, MaxLossRuns: MaxLossRuns, IntervalSlackMS: IntervalSlack.Milliseconds(), CauseOrder: CauseOrder,
	}
}

// RunLine is one row of the exclusion list.
type RunLine struct {
	ID         string      `json:"id"`
	Agent      string      `json:"agent"`
	Version    string      `json:"version"`
	Task       string      `json:"task"`
	Exclusions []Exclusion `json:"exclusions"`
	Effect     string      `json:"effect"`
}

// Counts are the run counts of one agent version.
type Counts struct {
	AgentVersion
	// Considered is every manifest run; Completed those in H3c and H3d;
	// Kept those in H3a, H3b and H2; Swept those the attack sweep covered.
	Considered int            `json:"considered"`
	Completed  int            `json:"completed"`
	Kept       int            `json:"kept"`
	Swept      int            `json:"swept"`
	ByRule     map[string]int `json:"excluded_by_rule"`
	// Incomplete counts runs the annotation says did not complete the task
	// (X5, reported, never excluded from H3); CompletionUnknown those with
	// no statement.
	NotCompleted      int `json:"task_not_completed"`
	CompletionUnknown int `json:"task_completion_not_stated"`
	// RunnerDisagrees counts runs whose recomputed outcome differs from the
	// runner's own verify-baseline.json outcome.
	RunnerDisagrees int `json:"runner_outcome_disagrees"`
	RunnerCompared  int `json:"runner_outcome_compared"`
}

// Results is results.json.
type Results struct {
	Schema      int          `json:"schema"`
	Inputs      Inputs       `json:"inputs"`
	Constants   Constants    `json:"constants"`
	Counts      []Counts     `json:"counts"`
	Slots       []SlotReport `json:"slots"`
	Excluded    []RunLine    `json:"excluded_runs"`
	Runs        []RunOutput  `json:"runs"`
	H1          *H1Results   `json:"h1,omitempty"`
	H2          *H2Results   `json:"h2,omitempty"`
	H3          *H3Results   `json:"h3,omitempty"`
	H4          *H4Results   `json:"h4,omitempty"`
	Verdicts    []Verdict    `json:"verdicts"`
	Halts       []string     `json:"halt_conditions"`
	Warnings    []string     `json:"warnings"`
	NotComputed []string     `json:"not_computed"`
}

const resultsSchema = 1

// Analyze runs the whole analysis and returns the results.
func Analyze(o Options) (*Results, error) {
	c, err := LoadCampaign(o.Campaign)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadDefault(o.Config)
	if err != nil {
		return nil, fmt.Errorf("the agent version config is needed for the strict version check (I-57): %w", err)
	}
	last := o.LastSeed
	if last == 0 {
		last = SeedLast
	}
	res := &Results{Schema: resultsSchema, Constants: constants(last)}
	res.Inputs = Inputs{
		Campaign: filepath.Base(filepath.Clean(o.Campaign)), ManifestSHA256: c.ManifestSHA256, ManifestCommit: c.Manifest.Commit, ManifestStamp: c.Manifest.Generated,
		Annotations: len(c.Annotations.Runs) > 0, AgentConfig: filepath.Base(cfg.Path), AgentConfigSHA256: fileSHA256(cfg.Path),
	}
	if o.Comparison != "" {
		res.Inputs.Comparison = filepath.Base(filepath.Clean(o.Comparison))
	}

	po := ProcessOptions{Config: cfg, Sweep: !o.NoSweep, SweepOpts: SweepOptions{LastSeed: last, Diagnostics: o.Diagnostics != ""}, Sensitivity: !o.NoSensitivity, LOO: !o.NoLOO, Pools: NewPools(c)}
	jobs := o.Jobs
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	runs := ParallelMap(len(c.Manifest.Runs), jobs, func(i int) RunOutput { return ProcessRun(c, c.Manifest.Runs[i], po) })

	if o.Diagnostics != "" {
		if err := writeDiagnostics(o.Diagnostics, runs); err != nil {
			return nil, err
		}
	}
	if o.MeasureCost != "" {
		if err := measureCost(o.MeasureCost, c); err != nil {
			return nil, err
		}
	}

	res.Slots = Slots(c)
	res.Counts, res.Excluded = countRuns(runs)
	res.H3 = BuildH3(runs, !o.NoSensitivity)
	if !o.NoSweep {
		res.H2 = BuildH2(runs, last)
	} else {
		res.NotComputed = append(res.NotComputed, "H2: the attack sweep was skipped (--no-sweep)")
	}
	if o.NoSensitivity {
		res.NotComputed = append(res.NotComputed, "H3 sensitivity: the agreement grid and the leave-one-out baseline were skipped (--no-sensitivity)")
	} else if o.NoLOO {
		res.NotComputed = append(res.NotComputed, "H3 sensitivity: the leave-one-out pooled baseline was skipped (--no-loo)")
	}
	if o.Comparison != "" {
		h1, err := BuildH1(o.Comparison)
		if err != nil {
			res.NotComputed = append(res.NotComputed, "H1: "+err.Error())
		} else {
			res.H1 = h1
		}
	} else {
		res.NotComputed = append(res.NotComputed, "H1: no comparison sweep directory was given (--comparison)")
	}
	res.H4 = &H4Results{Real: BuildH4b(runs)}
	if len(o.Overhead) == 0 {
		res.NotComputed = append(res.NotComputed, "H4a: no overhead benchmark results.json was given (--overhead)")
	}
	after := map[string]*BenchRun{}
	for _, spec := range o.OverheadAfter {
		label, path := splitLabel(spec)
		b, err := LoadBench(label, path)
		if err != nil {
			return nil, err
		}
		after[label] = b
	}
	for _, spec := range o.Overhead {
		label, path := splitLabel(spec)
		b, err := LoadBench(label, path)
		if err != nil {
			return nil, err
		}
		if a := after[label]; a != nil {
			b.AddDrift(a)
		}
		res.H4.Bench = append(res.H4.Bench, *b)
		res.Inputs.Overhead = append(res.Inputs.Overhead, label)
	}
	for _, spec := range o.OverheadAfter {
		label, _ := splitLabel(spec)
		found := false
		for _, spec2 := range o.Overhead {
			if l2, _ := splitLabel(spec2); l2 == label {
				found = true
			}
		}
		if !found {
			res.Warnings = append(res.Warnings, fmt.Sprintf("--overhead-after %q has no --overhead run of the same label, so no drift is computed for it", label))
		}
	}

	res.Runs = runs
	res.Verdicts, res.Halts = BuildVerdicts(res)
	res.Warnings = append(res.Warnings, warnings(res, runs)...)
	// The runs section keeps every per-run number except what the H2 section
	// already holds in full.
	for i := range runs {
		if a := runs[i].Attack; a != nil {
			cp := *a
			cp.Misses, cp.OutOfCapture, cp.Mislocation, cp.Contradictions = nil, nil, nil, nil
			runs[i].Attack = &cp
		}
	}
	return res, nil
}

// fileSHA256 is the hex SHA-256 of a file's content, "" when it cannot be read.
func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func splitLabel(spec string) (label, path string) {
	if i := strings.Index(spec, "="); i > 0 {
		return spec[:i], spec[i+1:]
	}
	return filepath.Base(spec), spec
}

func countRuns(runs []RunOutput) ([]Counts, []RunLine) {
	var counts []Counts
	var lines []RunLine
	for _, av := range agentVersions(runs) {
		c := Counts{AgentVersion: av, ByRule: map[string]int{}}
		for _, o := range runs {
			if o.Agent != av.Agent || o.Version != av.Version {
				continue
			}
			c.Considered++
			if o.Scope.Completed {
				c.Completed++
			}
			if o.Scope.Kept {
				c.Kept++
			}
			if o.Attack != nil {
				c.Swept++
			}
			seen := map[string]bool{}
			for _, e := range o.Exclusions {
				if !seen[e.Rule] {
					seen[e.Rule] = true
					c.ByRule[e.Rule]++
				}
			}
			switch {
			case o.Completed == nil:
				c.CompletionUnknown++
			case !*o.Completed:
				c.NotCompleted++
			}
			if o.RunnerAgrees != nil {
				c.RunnerCompared++
				if !*o.RunnerAgrees {
					c.RunnerDisagrees++
				}
			}
			if len(o.Exclusions) > 0 || o.SweepExclusion != nil {
				line := RunLine{ID: o.ID, Agent: o.Agent, Version: o.Version, Task: o.Task, Exclusions: append([]Exclusion(nil), o.Exclusions...)}
				if o.SweepExclusion != nil {
					line.Exclusions = append(line.Exclusions, *o.SweepExclusion)
				}
				switch {
				case !o.Scope.Completed:
					line.Effect = "out of every analysis"
				case !o.Scope.Kept:
					line.Effect = "out of H3a, H3b and H2; in H3c and H3d"
				default:
					line.Effect = "out of the H2 sweep only"
				}
				lines = append(lines, line)
			}
		}
		counts = append(counts, c)
	}
	return counts, lines
}

// warnings lists what a reader must see beside the numbers: instrument
// inconsistencies that are not halt conditions.
func warnings(res *Results, runs []RunOutput) []string {
	var w []string
	if res.H2 != nil && res.H2.Reduced {
		w = append(w, fmt.Sprintf("the attack sweep ran seeds %d to %d, not the registered %d to %d: its numbers are not the registered H2 numbers", SeedFirst, res.H2.LastSeed, SeedFirst, SeedLast))
	}
	for _, s := range res.Slots {
		if s.OverLimit {
			w = append(w, fmt.Sprintf("X4: %s has %d failed slot(s) of %d (%.0f%%), above the %.0f%% line: a finding about feasibility", s.Agent, s.FailedSlots, s.Slots, 100*(*s.FailedShare), 100*MaxFailedSlotShare))
		}
	}
	for _, c := range res.Counts {
		if c.RunnerDisagrees > 0 {
			w = append(w, fmt.Sprintf("%s %s: %d of %d run(s) have an outcome that differs from the runner's own verify-baseline.json", c.Agent, c.Version, c.RunnerDisagrees, c.RunnerCompared))
		}
	}
	for _, o := range runs {
		if o.ControlsDropped > 0 {
			w = append(w, fmt.Sprintf("X2: %s has %d control run(s) left out of the baseline for loss or a parse error", o.ID, o.ControlsDropped))
		}
		if o.Primary != nil && o.Primary.Error != "" {
			w = append(w, fmt.Sprintf("%s has no verdict: %s", o.ID, o.Primary.Error))
		}
		if o.LOONote != "" {
			w = append(w, fmt.Sprintf("%s: leave-one-out not computed: %s", o.ID, o.LOONote))
		}
		if o.Attack != nil {
			for _, e := range o.Attack.GeneratorErrors {
				w = append(w, fmt.Sprintf("%s: generator error: %s", o.ID, e))
			}
		}
	}
	return w
}

// writeJSON writes v as indented JSON with a trailing newline.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func writeDiagnostics(path string, runs []RunOutput) error {
	var out []DiagRun
	for _, o := range runs {
		if o.Attack != nil {
			out = append(out, o.Attack.Diag...)
		}
	}
	return writeJSON(path, struct {
		Note string    `json:"note"`
		Runs []DiagRun `json:"runs"`
	}{fmt.Sprintf("E-5 diagnostics of the attack sweep: %d runs that are ambiguous, have an unaccounted finding, or have a detectable mutation not detected, classified and located", len(out)), out})
}
