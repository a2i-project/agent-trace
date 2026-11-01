// Command analyze computes every number of the experiment protocol from a
// campaign directory: the false-positive and INCONCLUSIVE rates of honest runs
// (H3), the attack sweep over the same runs (H2), the comparison with other
// tools read from the comparison sweep's output (H1) and the overhead (H4),
// with the exclusion rules applied and every excluded run listed. It writes
// results.json, which holds each number, count and interval, and report.md,
// which holds the tables and one verdict line per registered hypothesis against
// the registered thresholds.
//
//	analyze --campaign OUTPUT_DIR [--out DIR] [--protocol FILE]
//	        [--comparison SWEEP_DIR] [--overhead LABEL=results.json]...
//	        [--seeds N] [--jobs N]
//
// The thresholds, seeds and strata common to all agents are constants in
// protocol.go; the per-agent targets are read from the protocol file
// (targets.go). The same inputs give byte-identical outputs.
//
// Exit codes: 0 done, 1 done and a halt condition of protocol 10.2 occurred,
// 3 usage or I/O error.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	_ "github.com/agent-trace/agent-trace/pkg/agent/codex"
	_ "github.com/agent-trace/agent-trace/pkg/agent/gemini"
)

const (
	exitHalt  = 1
	exitError = 3
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var o Options
	var overhead, overheadAfter repeated
	var seeds uint64
	fs.StringVar(&o.Campaign, "campaign", "", "Campaign directory: the manifest layout of scripts/capture-campaign.sh (required)")
	fs.StringVar(&o.Out, "out", "", "Where to write results.json and report.md (default: the campaign directory)")
	fs.StringVar(&o.Config, "config", "", "Agent version config (default as verify: $"+"AGENT_TRACE_CONFIG, else config/agents.json)")
	fs.StringVar(&o.Protocol, "protocol", "", "Protocol file of the per-agent targets (default: "+ProtocolFileName+" beside the agent version config)")
	fs.StringVar(&o.Comparison, "comparison", "", "Output directory of scripts/compare/sweep.py, for H1")
	fs.Var(&overhead, "overhead", "Overhead benchmark results.json as LABEL=PATH, for H4a. Repeatable (for example tmpfs and disk)")
	fs.Var(&overheadAfter, "overhead-after", "The same benchmark repeated after the campaign, LABEL=PATH with the label of an --overhead run: the difference is reported as machine drift")
	fs.Uint64Var(&seeds, "seeds", SeedLast, "Highest seed of the attack sweep. The registered sweep is 100; a smaller value bounds the cost and the report says the sweep is reduced")
	fs.IntVar(&o.Jobs, "jobs", 0, "Runs processed in parallel (default: the number of CPUs)")
	fs.BoolVar(&o.NoSweep, "no-sweep", false, "Skip the attack sweep (H2)")
	fs.BoolVar(&o.NoSensitivity, "no-sensitivity", false, "Skip the H3 sensitivity analyses (agreement grid and leave-one-out)")
	fs.BoolVar(&o.NoLOO, "no-loo", false, "Skip only the leave-one-out pooled baseline, the costliest sensitivity setting")
	fs.StringVar(&o.Diagnostics, "diagnostics", "", "Also write the E-5 Diagnose records of the sweep to this JSON file")
	fs.StringVar(&o.MeasureCost, "measure-cost", "", "Also time baseline building and verification of every run, sequentially, and write the timings to this JSON file. Timings vary between runs, so they stay out of results.json")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(errOut, "Usage: analyze --campaign DIR [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if o.Campaign == "" || fs.NArg() != 0 {
		fs.Usage()
		return exitError
	}
	o.Overhead, o.OverheadAfter, o.LastSeed = overhead, overheadAfter, seeds
	if seeds < SeedFirst || seeds > SeedLast {
		_, _ = fmt.Fprintf(errOut, "analyze: --seeds must be between %d and %d\n", SeedFirst, SeedLast)
		return exitError
	}
	if o.Out == "" {
		o.Out = o.Campaign
	}
	if err := os.MkdirAll(o.Out, 0o755); err != nil {
		_, _ = fmt.Fprintf(errOut, "analyze: %v\n", err)
		return exitError
	}
	res, err := Analyze(o)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "analyze: %v\n", err)
		return exitError
	}
	if err := writeJSON(filepath.Join(o.Out, "results.json"), res); err != nil {
		_, _ = fmt.Fprintf(errOut, "analyze: %v\n", err)
		return exitError
	}
	if err := os.WriteFile(filepath.Join(o.Out, "report.md"), []byte(Report(res)), 0o644); err != nil {
		_, _ = fmt.Fprintf(errOut, "analyze: %v\n", err)
		return exitError
	}
	for _, v := range res.Verdicts {
		_, _ = fmt.Fprintf(out, "%-14s %-13s %s\n", v.ID, v.Result, v.Scope)
	}
	_, _ = fmt.Fprintf(out, "wrote %s and %s\n", filepath.Join(o.Out, "results.json"), filepath.Join(o.Out, "report.md"))
	if len(res.Halts) > 0 {
		for _, h := range res.Halts {
			_, _ = fmt.Fprintf(errOut, "HALT: %s\n", h)
		}
		return exitHalt
	}
	return 0
}
