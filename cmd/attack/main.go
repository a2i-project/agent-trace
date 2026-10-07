// Command attack mutates a trajectory the way the threat model says an
// untrustworthy agent would, for evaluation. It reads a session through an
// adapter (or normalized JSON), applies one generator (omission, fabrication,
// substitution or interval widening), writes the mutated trajectory as
// normalized JSON and writes a record of what it changed. verify --normalized
// then checks the mutated trajectory against a capture, and the record says
// which entry any finding should name.
//
//	attack --kind substitution --n 2 --seed 7 --trajectory session.jsonl \
//	       --out mutated.json --record record.json
//	verify --normalized --agent claude-code --trajectory mutated.json \
//	       --ground-truth ground_truth.json --baseline baseline.json
//
// Exit codes: 0 written, 3 usage, I/O or a mutation the trajectory does not
// admit.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/agent"
	_ "github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	_ "github.com/agent-trace/agent-trace/pkg/agent/gemini"
	"github.com/agent-trace/agent-trace/pkg/attack"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const exitError = 3

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("attack", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var kind, trajectoryPath, outPath, recordPath, agentName, groundTruth, field, selectFlag string
	var n int
	var seed uint64
	var retime, normalized bool
	fs.StringVar(&kind, "kind", "", "Attack: omission, fabrication, substitution or interval-widening")
	fs.IntVar(&n, "n", 1, "How many entries to mutate or insert")
	fs.Uint64Var(&seed, "seed", 1, "Seed: the same trajectory, flags and seed give the same mutation")
	fs.StringVar(&trajectoryPath, "trajectory", "", "The honest trajectory: a session file an adapter reads, or normalized JSON with --normalized")
	fs.StringVar(&agentName, "agent", "", "Adapter that reads the trajectory ("+strings.Join(agent.Names(), ", ")+"). Default: detect, else generic")
	fs.BoolVar(&normalized, "normalized", false, "Read --trajectory as normalized trajectory JSON")
	fs.StringVar(&outPath, "out", "mutated.json", "Where to write the mutated trajectory (normalized JSON)")
	fs.StringVar(&recordPath, "record", "record.json", "Where to write the record of the mutation")
	fs.StringVar(&selectFlag, "select", "all", "Which entries may be chosen: all, or sensitive (credential and key files, data-moving commands, external connections)")
	fs.StringVar(&field, "field", "", "Substitution only: change this field (target, output_hash, exit_code, request_hash)")
	fs.BoolVar(&retime, "retime", false, "Omission only: move later claims earlier to close the hole in the timeline, which misplaces them against the real clock")
	fs.StringVar(&groundTruth, "avoid-ground-truth", "", "A capture's ground truth file: no fabricated or substituted target will equal anything observed in it, so a mutation cannot be true by accident")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if kind == "" || trajectoryPath == "" {
		_, _ = fmt.Fprintln(errOut, "attack: --kind and --trajectory are required")
		return exitError
	}

	var adapter agent.Adapter
	var tr models.Trajectory
	var err error
	if normalized {
		g, _ := agent.Lookup(agent.GenericName)
		adapter = g
		if agentName != "" {
			var ok bool
			if adapter, ok = agent.Lookup(agentName); !ok {
				_, _ = fmt.Fprintf(errOut, "attack: unknown agent %q (registered: %s)\n", agentName, strings.Join(agent.Names(), ", "))
				return exitError
			}
		}
		tr, _, err = g.Parse(trajectoryPath)
	} else {
		adapter, err = chooseAdapter(agentName, trajectoryPath)
		if err == nil {
			tr, _, err = adapter.Parse(trajectoryPath)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "attack: %v\n", err)
		return exitError
	}

	opt := attack.Options{N: n, Seed: seed}
	switch selectFlag {
	case "all":
	case "sensitive":
		opt.Select = attack.Sensitive
	default:
		_, _ = fmt.Fprintf(errOut, "attack: --select must be all or sensitive, got %q\n", selectFlag)
		return exitError
	}
	opt.Retime = retime
	if groundTruth != "" {
		avoid, err := observedTargets(adapter, tr, groundTruth)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "attack: %v\n", err)
			return exitError
		}
		opt.Avoid = avoid
	}

	var mutated models.Trajectory
	var rec attack.Record
	switch attack.Kind(strings.ReplaceAll(kind, "-", "_")) {
	case attack.Omission:
		mutated, rec, err = attack.Omit(tr, opt)
	case attack.Fabrication:
		mutated, rec, err = attack.Fabricate(tr, opt)
	case attack.Substitution:
		mutated, rec, err = attack.Substitute(tr, attack.SubstituteOptions{Options: opt, Field: field})
	case attack.IntervalWidening:
		mutated, rec, err = attack.Widen(tr, opt)
	default:
		_, _ = fmt.Fprintf(errOut, "attack: unknown kind %q (omission, fabrication, substitution, interval-widening)\n", kind)
		return exitError
	}
	if err != nil {
		if errors.Is(err, attack.ErrTooMany) {
			_, _ = fmt.Fprintf(errOut, "attack: this trajectory does not admit that mutation: %v\n", err)
		} else {
			_, _ = fmt.Fprintf(errOut, "attack: %v\n", err)
		}
		return exitError
	}

	if err := writeJSON(outPath, mutated); err != nil {
		_, _ = fmt.Fprintf(errOut, "attack: %v\n", err)
		return exitError
	}
	if err := writeJSON(recordPath, rec); err != nil {
		_, _ = fmt.Fprintf(errOut, "attack: %v\n", err)
		return exitError
	}
	_, _ = fmt.Fprintf(out, "%s: %d mutation(s), seed %d, %d claims in, %d out\n", rec.Kind, len(rec.Mutations), rec.Seed, len(tr), len(mutated))
	for _, m := range rec.Mutations {
		_, _ = fmt.Fprintf(out, "  %s\n", describe(m))
	}
	_, _ = fmt.Fprintf(out, "wrote %s and %s\n", outPath, recordPath)
	return 0
}

func describe(m attack.Mutation) string {
	switch m.Kind {
	case attack.Omission:
		return fmt.Sprintf("dropped entry %d: %s %q", m.OriginalIndex, m.Before.ActionType, m.Before.Target)
	case attack.Fabrication:
		return fmt.Sprintf("inserted at %d: %s %q", m.Index, m.After.ActionType, m.After.Target)
	case attack.Substitution:
		return fmt.Sprintf("entry %d %s: %q -> %q", m.OriginalIndex, m.Field, m.Old, m.New)
	default:
		return fmt.Sprintf("entry %d interval: %s -> %s", m.OriginalIndex, m.Old, m.New)
	}
}

// observedTargets is every target the capture observed after the adapter has
// normalized it, plus every claim's target, so a generated claim cannot be true.
func observedTargets(a agent.Adapter, tr models.Trajectory, path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	gt, err := models.ParseGroundTruthFile(data)
	if err != nil {
		return nil, fmt.Errorf("parse ground truth %s: %w", path, err)
	}
	in := agent.Prepare(a, tr, gt, nil, verification.Options{})
	avoid := map[string]bool{}
	for _, e := range in.Ground {
		avoid[e.Target] = true
	}
	for _, e := range gt.Events {
		avoid[e.Target] = true
	}
	for _, e := range tr {
		avoid[e.Target] = true
	}
	return avoid, nil
}

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

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
