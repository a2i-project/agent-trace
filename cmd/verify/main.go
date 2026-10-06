// Command verify is the verification-engine and reporting-layer half of the
// live harness: it loads a self-reported trajectory and an independently
// captured ground truth (e.g. written by `watch`), runs pkg/verification,
// and prints the FAITHFUL / NOT FAITHFUL verdict with a per-category
// breakdown. It is deliberately tier-agnostic -- it only knows about
// models.Trajectory, models.GroundTruth, and verification.Verify, so it
// keeps working unchanged as new tiers add probes, hash fields, and
// action types.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

func main() {
	var trajectoryPath, groundTruthPath string
	var slack time.Duration
	var ignoreExits bool

	flag.StringVar(&trajectoryPath, "trajectory", "", "Path to the self-reported trajectory JSON")
	flag.StringVar(&groundTruthPath, "ground-truth", "", "Path to the observed ground truth JSON (written by watch)")
	flag.DurationVar(&slack, "interval-slack", 0, "Widen each claim's interval by this much on both sides before checking the observed action falls inside it (for a trajectory clock that is not the kernel's)")
	flag.BoolVar(&ignoreExits, "ignore-exits", false, "Do not align process exits: for a trajectory format that cannot state an exit")
	flag.Parse()

	if trajectoryPath == "" || groundTruthPath == "" {
		log.Fatal("--trajectory and --ground-truth are required")
	}

	tr := loadTrajectory(trajectoryPath)
	gtFile := loadGroundTruth(groundTruthPath)

	v := verification.Verify(verification.Input{
		Claims:   tr,
		Ground:   gtFile.Events,
		RootPID:  gtFile.RootPID,
		Coverage: gtFile.Coverage,
		Options:  verification.Options{IntervalSlack: slack, IgnoreExits: ignoreExits},
	})

	fmt.Println("=== Agent-Trace Verification Report ===")
	fmt.Printf("trajectory:   %s (%d entries)\n", trajectoryPath, len(tr))
	fmt.Printf("ground truth: %s (%d events, root pid %d)\n", groundTruthPath, len(gtFile.Events), gtFile.RootPID)

	fmt.Println("\nAlignment (what the agent said against what it did at the top level):")
	fmt.Printf("  Corroborated: %d\n", len(v.Corroborated))
	fmt.Printf("  Mismatched:   %d  (claimed and observed at the same position, details disagree)\n", len(v.Mismatched))
	fmt.Printf("  Unwitnessed:  %d  (claimed by the agent, never observed)\n", len(v.Unwitnessed))
	fmt.Printf("  Unrecorded:   %d  (observed at the top level, never claimed)\n", len(v.Unrecorded))
	fmt.Printf("  Outside interval: %d  (observed outside the claimed interval)\n", len(v.OutsideInterval))
	if v.Ambiguous {
		fmt.Println("  note: more than one alignment is equally good, so the position a finding points at is one of several")
	}

	c := v.Coverage
	fmt.Println("\nCoverage (is every observed event explained by a claim?):")
	fmt.Printf("  Unexplained subtrees: %d  (commands nothing claims)\n", len(c.UnexplainedSubtrees))
	fmt.Printf("  Explained by a claimed command: %d events\n", c.Explained)
	fmt.Printf("  Explained by the baseline:      %d events\n", c.Baselined)
	fmt.Printf("  Outside the agent's tree:       %d events (reported, not the agent's)\n", len(c.Outside))
	fmt.Printf("  Unplaced (no pid):              %d events\n", len(c.Unknown))
	fmt.Printf("Capability:   %d  (listeners and sockets observed, never claimable, not part of the verdict)\n", len(v.Capability))

	printEntries("Unwitnessed", v.Unwitnessed)
	printEvents("Unrecorded", v.Unrecorded)
	printSubtrees(c.UnexplainedSubtrees)
	printPairs("Mismatched", v.Mismatched)
	printPairs("Outside interval", v.OutsideInterval)
	printEvents("Capability", v.Capability)
	printCompleteness(v.Completeness)

	fmt.Println()
	fmt.Printf("VERDICT: %s\n", v.Outcome)
	switch {
	case v.Outcome == verification.OutcomeInconclusive:
		fmt.Println("FAITHFUL cannot be asserted:")
		for _, r := range v.Reasons {
			fmt.Printf("  - %s\n", r)
		}
	case v.Advisory:
		fmt.Println("The ground truth is incomplete, so the findings above are advisory:")
		for _, r := range v.Reasons {
			fmt.Printf("  - %s\n", r)
		}
	}
	os.Exit(v.Outcome.ExitCode())
}

func printCompleteness(c verification.Completeness) {
	fmt.Println()
	if c.Complete {
		fmt.Println("Ground truth completeness: complete (no recorded event loss)")
	} else {
		fmt.Println("Ground truth completeness: INCOMPLETE")
		for _, r := range c.Reasons {
			fmt.Printf("  - %s\n", r)
		}
	}
	for _, n := range c.Notes {
		fmt.Printf("  note: %s\n", n)
	}
}

func loadTrajectory(path string) models.Trajectory {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		log.Fatalf("parse trajectory %s: %v", path, err)
	}
	return tr
}

func loadGroundTruth(path string) models.GroundTruthFile {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
	gt, err := models.ParseGroundTruthFile(data)
	if err != nil {
		log.Fatalf("parse ground truth %s: %v", path, err)
	}
	return gt
}

func printEntries(label string, entries []models.TrajectoryEntry) {
	if len(entries) == 0 {
		return
	}
	fmt.Printf("\n%s:\n", label)
	for _, e := range entries {
		fmt.Printf("  %s %-14s %s\n", e.Timestamp.Format(time.RFC3339Nano), e.ActionType, e.Target)
	}
}

func printEvents(label string, events []models.GroundTruthEvent) {
	if len(events) == 0 {
		return
	}
	fmt.Printf("\n%s:\n", label)
	for _, e := range events {
		fmt.Printf("  %s %-14s %s\n", e.Timestamp.Format(time.RFC3339Nano), e.ActionType, e.Target)
	}
}

func printSubtrees(cmds []*verification.Command) {
	if len(cmds) == 0 {
		return
	}
	fmt.Println("\nUnexplained subtrees:")
	for _, c := range cmds {
		target := "(forked and never exec'd)"
		if c.Exec != nil {
			target = c.Exec.Target
		}
		fmt.Printf("  pid %d %s  (%d events beneath it)\n", c.Process.PID, target, len(c.Content))
	}
}

// printPairs shows both sides of every pair with the fields that disagree, so
// it needs no changes as later tiers add fields to compare.
func printPairs(label string, pairs []verification.MatchedPair) {
	if len(pairs) == 0 {
		return
	}
	fmt.Printf("\n%s:\n", label)
	for _, p := range pairs {
		fmt.Printf("  claimed:  %s %s\n", p.Entry.ActionType, p.Entry.Target)
		fmt.Printf("  observed: %s %s\n", p.Event.ActionType, p.Event.Target)
		if len(p.Diffs) > 0 {
			fmt.Printf("    differs in: %v\n", p.Diffs)
		}
		fmt.Printf("    claimed:  exit_code=%s input_hash=%s output_hash=%s request_hash=%s\n",
			derefInt(p.Entry.ExitCode), derefStr(p.Entry.InputHash), derefStr(p.Entry.OutputHash), derefStr(p.Entry.RequestHash))
		fmt.Printf("    observed: exit_code=%s input_hash=%s output_hash=%s request_hash=%s\n",
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
