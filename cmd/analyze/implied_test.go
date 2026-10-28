package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	"github.com/agent-trace/agent-trace/pkg/attack"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The sweep verifies attacked runs with the adapter's harness-implied claims
// put back (attack.WithImplied). On the shapes fixture, whose Bash call has
// a harness-implied open, the honest run through the attack path then has no
// finding and agrees with the adapter path, and no attacked run carries a
// finding the honest run already had. Without the implied claims the same
// honest run has a finding: the harness's open they explain.
func TestTheSweepKeepsHarnessImpliedClaims(t *testing.T) {
	dir := "../../pkg/agent/claudecode/testdata/paired-2.1.296-shapes"
	ad := claudecode.Adapter{}
	claims, rep, err := ad.Parse(filepath.Join(dir, "shapes.session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	load := func(p string) models.GroundTruthFile {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		g, err := models.ParseGroundTruthFile(data)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "control-*.ground_truth.json"))
	var controls []models.GroundTruthFile
	for _, p := range paths {
		controls = append(controls, load(p))
	}
	s := &Session{ID: "shapes", Adapter: ad, Claims: claims, Report: rep, G: load(filepath.Join(dir, "shapes.ground_truth.json")), Controls: controls, Version: rep.AgentVersion}
	b, err := BuildBaseline(ad, rep.AgentVersion, controls, 1)
	if err != nil {
		t.Fatal(err)
	}
	own, implied := attack.WithoutImplied(claims)
	if implied == 0 {
		t.Fatal("the fixture has no harness-implied claim")
	}
	if v := verification.Verify(s.input(own, b)); v.Findings() == 0 {
		t.Fatal("without its implied claims the honest run has no finding: the test would prove nothing")
	}
	run := s.Sweep(b, SweepOptions{LastSeed: SeedFirst + 4})
	if run.PathArtifacts != 0 || len(run.Premise) != 0 {
		t.Errorf("honest run through the attack path: %d findings, premise differences %+v", run.PathArtifacts, run.Premise)
	}
	for _, tl := range run.Tallies {
		if tl.UnaccountedHonest != 0 {
			t.Errorf("%s n=%d: %d unaccounted findings already on the honest run", tl.Variant, tl.N, tl.UnaccountedHonest)
		}
	}
}
