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

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

func main() {
	var trajectoryPath, groundTruthPath string
	var delta time.Duration

	flag.StringVar(&trajectoryPath, "trajectory", "", "Path to the self-reported trajectory JSON")
	flag.StringVar(&groundTruthPath, "ground-truth", "", "Path to the observed ground truth JSON")
	flag.DurationVar(&delta, "delta", 2*time.Second, "Max timestamp difference allowed for a match (generous default for manually-run two-terminal sessions)")
	flag.Parse()

	if trajectoryPath == "" || groundTruthPath == "" {
		log.Fatal("--trajectory and --ground-truth are required")
	}

	tr := loadTrajectory(trajectoryPath)
	gtFile := loadGroundTruth(groundTruthPath)
	gt := gtFile.Events

	verdict := verification.Verify(tr, gt, matching.Config{Delta: delta})
	completeness := verification.Assess(gtFile.Coverage)

	fmt.Println("=== Agent-Trace Verification Report ===")
	fmt.Printf("trajectory:   %s (%d entries)\n", trajectoryPath, len(tr))
	fmt.Printf("ground truth: %s (%d events)\n", groundTruthPath, len(gt))
	fmt.Printf("delta:        %s\n", delta)

	fmt.Printf("\nCorroborated: %d\n", len(verdict.Corroborated))
	fmt.Printf("Unwitnessed:  %d  (claimed by the agent, never observed)\n", len(verdict.Unwitnessed))
	fmt.Printf("Unrecorded:   %d  (observed, never claimed)\n", len(verdict.Unrecorded))
	fmt.Printf("Mismatched:   %d  (claimed and observed, details disagree)\n", len(verdict.Mismatched))

	printEntries("Unwitnessed", verdict.Unwitnessed)
	printEvents("Unrecorded", verdict.Unrecorded)
	printMismatched(verdict.Mismatched)
	printCompleteness(completeness)

	outcome := verification.Conclude(verdict, completeness)
	fmt.Println()
	fmt.Printf("VERDICT: %s\n", outcome)
	if outcome == verification.OutcomeInconclusive {
		fmt.Println("The checks passed, but the ground truth may have lost events, so FAITHFUL cannot be asserted.")
	}
	if outcome == verification.OutcomeNotFaithful && !completeness.Complete {
		fmt.Println("Note: the ground truth is incomplete, so the findings above are advisory.")
	}
	os.Exit(outcome.ExitCode())
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

// printMismatched shows both sides of every mismatched pair. It always
// prints both lines rather than trying to guess which field disagreed, so
// it needs no changes as later tiers add fields (e.g. Tier 4 content hashes)
// to compare.
func printMismatched(pairs []verification.MatchedPair) {
	if len(pairs) == 0 {
		return
	}
	fmt.Println("\nMismatched:")
	for _, p := range pairs {
		fmt.Printf("  %s %s\n", p.Entry.ActionType, p.Entry.Target)
		fmt.Printf("    claimed:  exit_code=%s input_hash=%s output_hash=%s\n",
			derefInt(p.Entry.ExitCode), derefStr(p.Entry.InputHash), derefStr(p.Entry.OutputHash))
		fmt.Printf("    observed: exit_code=%s input_hash=%s output_hash=%s\n",
			derefInt(p.Event.ExitCode), derefStr(p.Event.InputHash), derefStr(p.Event.OutputHash))
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
