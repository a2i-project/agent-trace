package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/attack"
	"github.com/agent-trace/agent-trace/pkg/models"
)

const session = "../../pkg/agent/claudecode/testdata/paired-2.1.286/task.session.jsonl"
const groundTruth = "../../pkg/agent/claudecode/testdata/paired-2.1.286/task.ground_truth.json"

func attackCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func readTrajectory(t *testing.T, path string) models.Trajectory {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatalf("%s is not a valid trajectory: %v", path, err)
	}
	return tr
}

func readRecord(t *testing.T, path string) attack.Record {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec attack.Record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestEachKindWritesAValidTrajectoryAndARecord(t *testing.T) {
	for _, tc := range []struct {
		kind    string
		wantLen int // claims out, given 7 claims in and --n 2
	}{
		{"omission", 5}, {"fabrication", 9}, {"substitution", 7}, {"interval-widening", 7},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			dir := t.TempDir()
			outPath, recPath := filepath.Join(dir, "m.json"), filepath.Join(dir, "r.json")
			code, out, errOut := attackCmd(t, "--kind", tc.kind, "--n", "2", "--seed", "3", "--trajectory", session, "--out", outPath, "--record", recPath)
			if code != 0 {
				t.Fatalf("exit %d: %s %s", code, out, errOut)
			}
			tr := readTrajectory(t, outPath)
			rec := readRecord(t, recPath)
			if len(tr) != tc.wantLen || len(rec.Mutations) != 2 || rec.Seed != 3 || string(rec.Kind) != strings.ReplaceAll(tc.kind, "-", "_") {
				t.Errorf("%d claims out, record %+v", len(tr), rec)
			}
			if !strings.Contains(out, "wrote "+outPath) {
				t.Errorf("output: %s", out)
			}
		})
	}
}

func TestTheSameSeedGivesTheSameMutation(t *testing.T) {
	dir := t.TempDir()
	var outs [2][]byte
	for i := range outs {
		p := filepath.Join(dir, "m"+string(rune('a'+i))+".json")
		if code, _, e := attackCmd(t, "--kind", "substitution", "--n", "2", "--seed", "9", "--trajectory", session, "--out", p, "--record", filepath.Join(dir, "r.json")); code != 0 {
			t.Fatal(e)
		}
		outs[i], _ = os.ReadFile(p)
	}
	if !bytes.Equal(outs[0], outs[1]) {
		t.Error("two runs with one seed differ")
	}
}

func TestMutatedOutputRoundTripsAsNormalizedInput(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.json")
	if code, _, e := attackCmd(t, "--kind", "fabrication", "--n", "1", "--trajectory", session, "--out", first, "--record", filepath.Join(dir, "r1.json")); code != 0 {
		t.Fatal(e)
	}
	second := filepath.Join(dir, "second.json")
	code, out, errOut := attackCmd(t, "--normalized", "--kind", "omission", "--n", "1", "--trajectory", first, "--out", second, "--record", filepath.Join(dir, "r2.json"))
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	if got := len(readTrajectory(t, second)); got != 7 {
		t.Errorf("a fabrication then an omission leaves %d claims, want 7", got)
	}
}

func TestToolSurvivesTheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := filepath.Join(dir, "m.json")
	if code, _, e := attackCmd(t, "--kind", "interval-widening", "--n", "1", "--trajectory", session, "--out", m, "--record", filepath.Join(dir, "r.json")); code != 0 {
		t.Fatal(e)
	}
	for _, e := range readTrajectory(t, m) {
		if e.Tool == "" {
			t.Errorf("claim %s %s lost its tool: the adapter's per-tool declaration needs it", e.ActionType, e.Target)
		}
	}
}

func TestAvoidGroundTruthKeepsAMutationFromBeingTrueByAccident(t *testing.T) {
	data, err := os.ReadFile(groundTruth)
	if err != nil {
		t.Fatal(err)
	}
	gt, _ := models.ParseGroundTruthFile(data)
	observed := map[string]bool{}
	for _, e := range gt.Events {
		observed[e.Target] = true
	}
	dir := t.TempDir()
	for seed := 0; seed < 25; seed++ {
		m := filepath.Join(dir, "m.json")
		rp := filepath.Join(dir, "r.json")
		if code, _, e := attackCmd(t, "--kind", "fabrication", "--n", "3", "--seed", string(rune('0'+seed%10))+"", "--trajectory", session, "--avoid-ground-truth", groundTruth, "--out", m, "--record", rp); code != 0 {
			t.Fatal(e)
		}
		for _, mu := range readRecord(t, rp).Mutations {
			if observed[mu.After.Target] {
				t.Fatalf("fabricated %q, which the capture observed", mu.After.Target)
			}
		}
	}
}

func TestSelectSensitiveAdmitsNothingWhenNothingIsSensitive(t *testing.T) {
	code, _, errOut := attackCmd(t, "--kind", "omission", "--select", "sensitive", "--trajectory", session, "--out", filepath.Join(t.TempDir(), "m.json"))
	if code != exitError || !strings.Contains(errOut, "does not admit") {
		t.Errorf("exit %d, stderr %q: asking for a sensitive omission from a trajectory with none must be an error", code, errOut)
	}
}

func TestErrorsAreExitThreeAndWriteNothing(t *testing.T) {
	dir := t.TempDir()
	m, r := filepath.Join(dir, "m.json"), filepath.Join(dir, "r.json")
	for name, args := range map[string][]string{
		"no flags":         {},
		"no trajectory":    {"--kind", "omission"},
		"unknown kind":     {"--kind", "nope", "--trajectory", session},
		"unknown agent":    {"--kind", "omission", "--agent", "nope", "--trajectory", session},
		"missing file":     {"--kind", "omission", "--trajectory", filepath.Join(dir, "none")},
		"bad select":       {"--kind", "omission", "--select", "x", "--trajectory", session},
		"too many":         {"--kind", "omission", "--n", "99", "--trajectory", session},
		"zero":             {"--kind", "omission", "--n", "0", "--trajectory", session},
		"unknown field":    {"--kind", "substitution", "--field", "timestamp", "--trajectory", session},
		"no such exit":     {"--kind", "substitution", "--field", "exit_code", "--trajectory", session},
		"avoid not a file": {"--kind", "fabrication", "--avoid-ground-truth", filepath.Join(dir, "none"), "--trajectory", session},
		"unknown flag":     {"--nope"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, errOut := attackCmd(t, append(args, "--out", m, "--record", r)...)
			if code != exitError || errOut == "" {
				t.Errorf("exit %d, stderr %q, want exit %d with a message", code, errOut, exitError)
			}
			if _, err := os.Stat(m); err == nil {
				t.Error("a mutated trajectory was written for a failed run")
			}
		})
	}
}
