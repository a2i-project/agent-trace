// Command baseline measures a harness's own activity from control runs. Give
// the agent a task that claims nothing, record it with watch, and pass the
// ground truth files here: everything the agent did anyway is, by construction,
// the harness. Several runs are better than one, because only what every run
// did becomes a rule and the rest is listed as unstable.
//
//	baseline --agent claude-code --agent-version 2.1.286 --out baseline.json run1.json run2.json run3.json
//
// verify then reads the result with --baseline.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	_ "github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	_ "github.com/agent-trace/agent-trace/pkg/agent/gemini"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var agentName, version, outPath string
	fs.StringVar(&agentName, "agent", "", "Adapter that normalizes the control runs ("+strings.Join(agent.Names(), ", ")+")")
	fs.StringVar(&version, "agent-version", "", "Version of the agent that was run: a baseline holds for one version only")
	fs.StringVar(&outPath, "out", "baseline.json", "Where to write the baseline")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(errOut, "Usage: baseline --agent NAME --agent-version V [--out FILE] CONTROL_RUN.json...")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if agentName == "" || version == "" || fs.NArg() == 0 {
		fs.Usage()
		return 3
	}
	a, ok := agent.Lookup(agentName)
	if !ok {
		_, _ = fmt.Fprintf(errOut, "baseline: unknown agent %q (registered: %s)\n", agentName, strings.Join(agent.Names(), ", "))
		return 3
	}

	var runs []models.GroundTruthFile
	for _, path := range fs.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "baseline: %v\n", err)
			return 3
		}
		f, err := models.ParseGroundTruthFile(data)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "baseline: parse %s: %v\n", path, err)
			return 3
		}
		// A control run that lost events would leave the baseline short, and a
		// short baseline reads as false omissions later.
		if f.Coverage == nil {
			_, _ = fmt.Fprintf(errOut, "baseline: %s has no coverage record, so what it lost is unknown\n", path)
			return 3
		}
		if c := verification.Assess(f.Coverage); !c.Complete {
			_, _ = fmt.Fprintf(errOut, "baseline: %s lost events, so a baseline from it would be short: %s\n", path, strings.Join(c.Reasons, "; "))
			return 3
		}
		runs = append(runs, f)
	}

	b, err := agent.Capture(a, version, runs, time.Now())
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "baseline: %v\n", err)
		return 3
	}
	if err := agent.SaveBaseline(outPath, b); err != nil {
		_, _ = fmt.Fprintf(errOut, "baseline: %v\n", err)
		return 3
	}
	_, _ = fmt.Fprintf(out, "wrote %s: %d rule(s) every one of %d run(s) performed, %d unstable action(s) left out\n", outPath, len(b.Rules), b.Runs, len(b.Unstable))
	if b.Runs == 1 {
		_, _ = fmt.Fprintln(out, "note: one control run cannot tell stable activity from incidental activity; capture at least three")
	}
	return 0
}
