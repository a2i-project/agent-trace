package main

import (
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/attack"
)

// Every threshold, seed, selection and stratum of the registered experiment
// that applies to all agents lives in this file, and nowhere else in the
// command; the per-agent targets (H3d's FAITHFUL bar, H3c's pilot range, the
// tool-heavy tasks) and the registration's name live in the protocol file
// (targets.go, E-8). The freeze pins the registration by pinning the two.
// Each constant names the section of
// docs/eval/experiment_protocol_v2.md (the protocol) or of
// docs/eval/decisions-2026-10-26.md (the decisions, which override it) it
// mirrors. A bar that moves after the first campaign run is a deviation
// (protocol 11.2), not an edit of this file.

// Estimator rules, protocol section 4.
const (
	// BootstrapResamples and BootstrapSeed are the cluster bootstrap's.
	BootstrapResamples        = 10000
	BootstrapSeed      uint64 = 20261018
	// ConfidenceLevel is the two-sided level of every interval, ZScore95 its
	// normal quantile for the Wilson interval, and OneSidedAlpha the exact
	// one-sided Clopper-Pearson bound's error rate.
	ConfidenceLevel = 0.95
	ZScore95        = 1.959963984540054
	OneSidedAlpha   = 0.05
)

// H3, protocol section 4 and decision D5.
const (
	// NearZeroFP is H3a's near-zero bar: a point estimate above it refutes.
	NearZeroFP = 0.05
)

// PrimaryAgreement is the baseline agreement of every primary number: a rule
// needs one of five controls (protocol 6.4). AgreementGrid is the sensitivity
// grid 1/5 to 5/5 (protocol 4, H3 sensitivity analyses).
const PrimaryAgreement = 0.2

var AgreementGrid = []Agreement{{"1/5", 0.2}, {"2/5", 0.4}, {"3/5", 0.6}, {"4/5", 0.8}, {"5/5", 1.0}}

// LOOAgreement is the agreement of the leave-one-out pooled baseline over n
// pooled controls: any one control, 1/n, as the capture script's own default
// is one of its controls (the user's reading of 2026-10-26). A fixed fraction
// would ask a rule of about 59 of 295 pooled controls and keep out the rare
// harness activity pooling is meant to explain.
func LOOAgreement(n int) float64 {
	if n <= 0 {
		return 1
	}
	return 1 / float64(n)
}

// LOOAgreementLabel describes LOOAgreement in results.json.
const LOOAgreementLabel = "1/N of the pooled controls (any one control)"

// Agreement is one setting of the sensitivity grid.
type Agreement struct {
	Label string  `json:"label"`
	Value float64 `json:"value"`
}

// IntervalSlack is verify's default (cmd/verify --interval-slack), which the
// capture script's own verify runs use.
const IntervalSlack = 500 * time.Millisecond

// HeldOutPrefix marks a held-out task (decision D8): the campaign runner
// names a task the user wrote outside the repository heldout:NAME. Every
// other task is development, the lane-written `long` included (D8: pilot and
// development only). The held-out stratum is reported apart.
const HeldOutPrefix = "heldout:"

// IsHeldOut says whether a task is held out (D8).
func IsHeldOut(task string) bool { return strings.HasPrefix(task, HeldOutPrefix) }

// Exclusion rule names, protocol 10.1.
const (
	X1 = "X1" // task run with a loss counter set
	X2 = "X2" // control run with loss, left out of the baseline
	X3 = "X3" // version changed during the capture
	X4 = "X4" // harness error
	X5 = "X5" // task not completed, or fewer than two claims for the sweep
	X6 = "X6" // user intervened
)

// MaxFailedSlotShare is X4's feasibility line: more failed slots than this
// per agent is itself a finding.
const MaxFailedSlotShare = 0.10

// MinClaimsForSweep is X5's bound: the generators need two claims.
const MinClaimsForSweep = 2

// Attack sweep, protocol 5.3 and 5.6.
const (
	// SeedFirst and SeedLast are the registered seeds, inclusive.
	SeedFirst uint64 = 1
	SeedLast  uint64 = 100
)

// Variant names of the sweep. A selection of "sensitive" is secondary, every
// other variant primary (protocol 5.3).
const (
	SelUniform   = "uniform"
	SelSensitive = "sensitive"
)

// GenSpec is one row of the protocol's generator table.
type GenSpec struct {
	Variant string      `json:"variant"`
	Kind    attack.Kind `json:"kind"`
	Select  string      `json:"select"`
	Retime  bool        `json:"retime,omitempty"`
	Field   string      `json:"field,omitempty"`
	N       int         `json:"n"`
	// Exhaustive: every admissible claim position, no seeds.
	Exhaustive bool `json:"exhaustive,omitempty"`
}

// Primary says whether the row has the primary (uniform) selection; the
// sensitive rows are secondary (protocol 5.3).
func (g GenSpec) Primary() bool { return g.Select == SelUniform }

// InVerdict says whether the row counts toward the H2a to H2c verdicts: a
// primary row that is not a retimed omission. Retimed omissions are reported
// apart, with the runs they push outside their interval (protocol 4, H2 "also
// reported"; the user's reading of 2026-10-26).
func (g GenSpec) InVerdict() bool { return g.Primary() && !g.Retime }

// SubstituteFields are the fields of the per-field runs (protocol 5.3):
// one run of seeds for each field the agent's claims carry.
var SubstituteFields = []string{attack.FieldTarget, attack.FieldOutputHash, attack.FieldExitCode, attack.FieldRequestHash}

// GenSpecs lists the registered mutations in a fixed order. The seeded rows run
// seeds SeedFirst to SeedLast; the command's --seeds flag may stop earlier and
// records the reduction.
func GenSpecs() []GenSpec {
	var out []GenSpec
	omit := func(variant, sel string, retime bool) {
		for n := 1; n <= 3; n++ {
			out = append(out, GenSpec{Variant: variant, Kind: attack.Omission, Select: sel, Retime: retime, N: n, Exhaustive: n == 1})
		}
	}
	omit("omit", SelUniform, false)
	omit("omit-sensitive", SelSensitive, false)
	omit("omit-retime", SelUniform, true)
	for n := 1; n <= 3; n++ {
		out = append(out, GenSpec{Variant: "fabricate", Kind: attack.Fabrication, Select: SelUniform, N: n})
	}
	for n := 1; n <= 3; n++ {
		out = append(out, GenSpec{Variant: "substitute", Kind: attack.Substitution, Select: SelUniform, N: n})
	}
	for n := 1; n <= 3; n++ {
		out = append(out, GenSpec{Variant: "substitute-sensitive", Kind: attack.Substitution, Select: SelSensitive, N: n})
	}
	for _, f := range SubstituteFields {
		out = append(out, GenSpec{Variant: "substitute-field-" + f, Kind: attack.Substitution, Select: SelUniform, Field: f, N: 1})
	}
	return out
}

// H4a limits, decision D3 (deployment-argued, stated as set after the pilot).
const (
	// MaxWallRatio is the median workload wall ratio under `all` on the
	// workloads named in WallRatioWorkloads.
	MaxWallRatio = 1.15
	// MaxFixedCostSeconds is the fixed cost per session (start-up plus drain).
	MaxFixedCostSeconds = 5.0
	// MaxWatchRSSMiB is the peak resident set of the watch process tree.
	MaxWatchRSSMiB = 256.0
	// MaxLossRuns is the number of runs under `all` with any loss: zero.
	MaxLossRuns = 0
)

// WallRatioWorkloads names the synthetic workloads the wall ratio limit
// applies to, as the benchmark names them (workload and size).
var WallRatioWorkloads = []string{"shell-100", "shell-1000"}

// H4Condition is the benchmark condition the limits apply to.
const H4Condition = "all"

// Names of the comparison tool rows of the H1 table (protocol 4, H1), as
// scripts/compare/sweep.py writes them.
const (
	ToolHalo   = "halo-record"
	ToolSignet = "signet"
	ToolRT     = "reproducible-trajectories"
)
