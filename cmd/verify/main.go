// Command verify loads a self-reported trajectory and an independently captured
// ground truth (written by watch), runs pkg/verification and prints the
// FAITHFUL, NOT FAITHFUL or INCONCLUSIVE verdict with the alignment and the
// coverage reported separately. An agent adapter reads the agent's own session
// format and supplies what the agent does differently; without one, the
// trajectory is read in the normalized JSON form.
//
// Exit codes: 0 FAITHFUL, 1 NOT FAITHFUL, 2 INCONCLUSIVE, 3 usage or I/O error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	_ "github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	_ "github.com/agent-trace/agent-trace/pkg/agent/gemini"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const exitError = 3

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var trajectoryPath, groundTruthPath, agentName, baselinePath string
	var slack time.Duration
	var ignoreExits bool
	fs.StringVar(&trajectoryPath, "trajectory", "", "Path to the trajectory: the agent's own session file when an adapter reads it, or normalized trajectory JSON")
	fs.StringVar(&groundTruthPath, "ground-truth", "", "Path to the observed ground truth JSON (written by watch)")
	fs.StringVar(&agentName, "agent", "", "Adapter that reads the trajectory ("+strings.Join(agent.Names(), ", ")+"). Default: detect from the file, else generic")
	fs.StringVar(&baselinePath, "baseline", "", "Harness baseline measured by a null-task run (see cmd/baseline). Without one the harness's own activity is reported as unexplained")
	fs.DurationVar(&slack, "interval-slack", 500*time.Millisecond, "Widen each claim's interval by this much on both sides before checking the observed action falls inside it: the probes and the agent do not share a clock")
	fs.BoolVar(&ignoreExits, "ignore-exits", false, "Do not align process exits even if the adapter's format records them")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if trajectoryPath == "" || groundTruthPath == "" {
		_, _ = fmt.Fprintln(errOut, "verify: --trajectory and --ground-truth are required")
		return exitError
	}

	adapter, err := chooseAdapter(agentName, trajectoryPath)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "verify: %v\n", err)
		return exitError
	}
	tr, rep, err := adapter.Parse(trajectoryPath)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "verify: read trajectory %s with the %s adapter: %v\n", trajectoryPath, adapter.Name(), err)
		return exitError
	}
	data, err := os.ReadFile(groundTruthPath)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "verify: %v\n", err)
		return exitError
	}
	gt, err := models.ParseGroundTruthFile(data)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "verify: parse ground truth %s: %v\n", groundTruthPath, err)
		return exitError
	}

	var baseline *agent.Baseline
	var measured verification.Baseline
	if baselinePath != "" {
		b, err := agent.LoadBaseline(baselinePath)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "verify: %v\n", err)
			return exitError
		}
		if b.Agent != adapter.Name() {
			_, _ = fmt.Fprintf(errOut, "verify: baseline %s was captured for %q, not %q\n", baselinePath, b.Agent, adapter.Name())
			return exitError
		}
		baseline, measured = &b, b.Predicate(gt.Workspace)
	} else if adapter.Name() != agent.GenericName {
		rep.Degradations = append(rep.Degradations, "no baseline supplied: the harness's own activity is reported as unexplained (08 V7)")
	}

	opts := verification.Options{IntervalSlack: slack}
	in := agent.Prepare(adapter, tr, gt, measured, opts)
	in.Options.IgnoreExits = in.Options.IgnoreExits || ignoreExits
	v := verification.Verify(in)

	report(out, reportInput{
		trajectoryPath: trajectoryPath, groundTruthPath: groundTruthPath, adapter: adapter.Name(),
		parse: rep, baseline: baseline, entries: len(tr), gt: gt, verdict: v,
	})
	return v.Outcome.ExitCode()
}

// chooseAdapter picks the adapter by name, or detects it, or falls back to the
// generic one when nothing recognises the file. An ambiguous detection is an
// error: guessing between two readings of one file would be silent.
func chooseAdapter(name, path string) (agent.Adapter, error) {
	if name != "" {
		a, ok := agent.Lookup(name)
		if !ok {
			return nil, fmt.Errorf("unknown agent %q (registered: %s)", name, strings.Join(agent.Names(), ", "))
		}
		return a, nil
	}
	a, err := agent.Detect(path)
	switch {
	case err == nil:
		return a, nil
	case errors.Is(err, agent.ErrNoMatch):
		g, _ := agent.Lookup(agent.GenericName)
		return g, nil
	default:
		return nil, err
	}
}

type reportInput struct {
	trajectoryPath, groundTruthPath, adapter string
	parse                                    agent.Report
	baseline                                 *agent.Baseline
	entries                                  int
	gt                                       models.GroundTruthFile
	verdict                                  verification.Verdict
}

func report(w io.Writer, r reportInput) {
	v := r.verdict
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

	p("=== Agent-Trace Verification Report ===\n")
	p("trajectory:   %s (%d entries, read by the %s adapter)\n", r.trajectoryPath, r.entries, r.adapter)
	p("ground truth: %s (%d events, root pid %d)\n", r.groundTruthPath, len(r.gt.Events), r.gt.RootPID)
	if r.baseline != nil {
		p("baseline:     %s %s, %d rule(s) from %d control run(s)\n", r.baseline.Agent, r.baseline.AgentVersion, len(r.baseline.Rules), r.baseline.Runs)
	}
	printParse(w, r.parse)

	p("\nAlignment (what the agent said against what it did at the top level):\n")
	p("  Corroborated: %d\n", len(v.Corroborated))
	p("  Mismatched:   %d  (claimed and observed at the same position, details disagree)\n", len(v.Mismatched))
	p("  Unwitnessed:  %d  (claimed by the agent, never observed)\n", len(v.Unwitnessed))
	p("  Unrecorded:   %d  (observed at the top level, never claimed)\n", len(v.Unrecorded))
	p("  Outside interval: %d  (observed outside the claimed interval)\n", len(v.OutsideInterval))
	if v.Ambiguous {
		p("  note: more than one alignment is equally good, so the position a finding points at is one of several\n")
	}

	c := v.Coverage
	p("\nCoverage (is every observed event explained by a claim?):\n")
	p("  Unexplained subtrees: %d  (commands nothing claims)\n", len(c.UnexplainedSubtrees))
	p("  Explained by a claimed command: %d events\n", c.Explained)
	p("  Explained by the baseline:      %d events\n", c.Baselined)
	p("  Quiet forks:                    %d (forked, never exec'd, nothing observed: nothing to explain)\n", len(c.Quiet))
	p("  Outside the agent's tree:       %d events (reported, not the agent's)\n", len(c.Outside))
	p("  Unplaced (no pid):              %d events\n", len(c.Unknown))
	p("Capability:   %d  (listeners and sockets observed, never claimable, not part of the verdict)\n", len(v.Capability))

	printEntries(w, "Unwitnessed", v.Unwitnessed)
	printEvents(w, "Unrecorded", v.Unrecorded)
	printSubtrees(w, c.UnexplainedSubtrees)
	printPairs(w, "Mismatched", v.Mismatched)
	printPairs(w, "Outside interval", v.OutsideInterval)
	printEvents(w, "Capability", v.Capability)
	printCompleteness(w, v.Completeness)

	p("\nVERDICT: %s\n", v.Outcome)
	switch {
	case v.Outcome == verification.OutcomeInconclusive:
		p("FAITHFUL cannot be asserted:\n")
		for _, reason := range v.Reasons {
			p("  - %s\n", reason)
		}
	case v.Advisory:
		p("The ground truth is incomplete, so the findings above are advisory:\n")
		for _, reason := range v.Reasons {
			p("  - %s\n", reason)
		}
	}
}

func printParse(w io.Writer, r agent.Report) {
	if r.ToolCalls > 0 || len(r.UnmappedByTool) > 0 {
		_, _ = fmt.Fprintf(w, "session:      %d tool call(s) became %d claim(s)\n", r.ToolCalls, r.Entries)
	}
	if len(r.UnmappedByTool) > 0 {
		names := make([]string, 0, len(r.UnmappedByTool))
		for n := range r.UnmappedByTool {
			names = append(names, n)
		}
		sort.Strings(names)
		parts := make([]string, len(names))
		for i, n := range names {
			parts[i] = fmt.Sprintf("%s x%d", n, r.UnmappedByTool[n])
		}
		_, _ = fmt.Fprintf(w, "  produced no claim: %s\n", strings.Join(parts, ", "))
	}
	if len(r.UnknownTools) > 0 {
		_, _ = fmt.Fprintf(w, "  WARNING tools with no mapping that may have acted: %s\n", strings.Join(r.UnknownTools, ", "))
	}
	for _, e := range r.ParseErrors {
		_, _ = fmt.Fprintf(w, "  parse error: %s\n", e)
	}
	for _, d := range r.Degradations {
		_, _ = fmt.Fprintf(w, "  limitation: %s\n", d)
	}
}

func printCompleteness(w io.Writer, c verification.Completeness) {
	_, _ = fmt.Fprintln(w)
	if c.Complete {
		_, _ = fmt.Fprintln(w, "Ground truth completeness: complete (no recorded event loss)")
	} else {
		_, _ = fmt.Fprintln(w, "Ground truth completeness: INCOMPLETE")
		for _, r := range c.Reasons {
			_, _ = fmt.Fprintf(w, "  - %s\n", r)
		}
	}
	for _, n := range c.Notes {
		_, _ = fmt.Fprintf(w, "  note: %s\n", n)
	}
}

func printEntries(w io.Writer, label string, entries []models.TrajectoryEntry) {
	if len(entries) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s:\n", label)
	for _, e := range entries {
		_, _ = fmt.Fprintf(w, "  %s %-14s %s\n", e.Timestamp.Format(time.RFC3339Nano), e.ActionType, e.Target)
	}
}

func printEvents(w io.Writer, label string, events []models.GroundTruthEvent) {
	if len(events) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s:\n", label)
	for _, e := range events {
		_, _ = fmt.Fprintf(w, "  %s %-14s %s\n", e.Timestamp.Format(time.RFC3339Nano), e.ActionType, e.Target)
	}
}

func printSubtrees(w io.Writer, cmds []*verification.Command) {
	if len(cmds) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "\nUnexplained subtrees:")
	for _, c := range cmds {
		target := "(forked and never exec'd)"
		if c.Exec != nil {
			target = c.Exec.Target
		}
		_, _ = fmt.Fprintf(w, "  pid %d %s  (%d events beneath it)\n", c.Process.PID, target, len(c.Content))
	}
}

// printPairs shows both sides of every pair with the fields that disagree, so
// it needs no changes as later tiers add fields to compare.
func printPairs(w io.Writer, label string, pairs []verification.MatchedPair) {
	if len(pairs) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s:\n", label)
	for _, p := range pairs {
		_, _ = fmt.Fprintf(w, "  claimed:  %s %s\n", p.Entry.ActionType, p.Entry.Target)
		_, _ = fmt.Fprintf(w, "  observed: %s %s\n", p.Event.ActionType, p.Event.Target)
		if len(p.Diffs) > 0 {
			_, _ = fmt.Fprintf(w, "    differs in: %v\n", p.Diffs)
		}
		_, _ = fmt.Fprintf(w, "    claimed:  exit_code=%s input_hash=%s output_hash=%s request_hash=%s\n",
			derefInt(p.Entry.ExitCode), derefStr(p.Entry.InputHash), derefStr(p.Entry.OutputHash), derefStr(p.Entry.RequestHash))
		_, _ = fmt.Fprintf(w, "    observed: exit_code=%s input_hash=%s output_hash=%s request_hash=%s\n",
			derefInt(p.Event.ExitCode), derefStr(p.Event.InputHash), derefStr(p.Event.OutputHash), derefStr(p.Event.RequestHash))
	}
}

func derefStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func derefInt(i *int32) string {
	if i == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%d", *i)
}
