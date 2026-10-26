package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The campaign directory is the layout scripts/capture-campaign.sh writes:
//
//	OUTPUT_DIR/manifest.json
//	OUTPUT_DIR/<agent>-<version>/<task>[-content]/run-NN/   one task run
//	    <task>.session.jsonl | <task>.conversation.db, <task>.ground_truth.json,
//	    control-N.ground_truth.json, baseline.json, verify*.json, run.json
//
// The command reads the manifest for what ran, and the run directories for
// the raw files it re-verifies in process. A run whose controls were taken by
// another run (controls.taken false) names that directory in controls.from.
// The manifest holds absolute paths of the machine that recorded it, so every
// path is resolved again under the campaign directory when it does not exist
// as written.

// Manifest is manifest.json, the fields this command reads.
type Manifest struct {
	Schema    int         `json:"schema"`
	Generated string      `json:"generated"`
	Commit    string      `json:"commit"`
	Runs      []RunRecord `json:"runs"`
}

// RunRecord is one run of the manifest (run.json).
type RunRecord struct {
	Agent      string  `json:"agent"`
	Version    string  `json:"version"`
	Task       string  `json:"task"`
	Run        int     `json:"run"`
	Mode       string  `json:"mode"`
	ControlSet string  `json:"control_set"`
	Dir        string  `json:"dir"`
	Status     string  `json:"status"`
	ExitStatus int     `json:"exit_status"`
	Start      string  `json:"start"`
	End        string  `json:"end"`
	DurationS  float64 `json:"duration_s"`
	Controls   struct {
		Taken bool   `json:"taken"`
		From  string `json:"from"`
		Count *int   `json:"count"`
	} `json:"controls"`
	Paths   map[string]*string `json:"paths"`
	Verdict struct {
		WithoutBaseline *RecordedVerdict `json:"without_baseline"`
		WithBaseline    *RecordedVerdict `json:"with_baseline"`
	} `json:"verdict"`
	Scale *ScaleRecord `json:"scale"`
	// Cost is optional: what the runner measured around the capture and the
	// current manifest does not carry (start-up, drain, watch CPU and peak
	// RSS). Absent means not measured.
	Cost *CostRecord `json:"cost"`
}

// RecordedVerdict is the runner's own verify output summary, kept to compare
// with the verdict this command recomputes.
type RecordedVerdict struct {
	Outcome   string `json:"outcome"`
	Findings  int    `json:"findings"`
	ToolCalls int    `json:"tool_calls"`
	Claims    int    `json:"claims"`
}

// ScaleRecord is the manifest's scale record of a run.
type ScaleRecord struct {
	Events struct {
		Total int `json:"total"`
	} `json:"events"`
	Processes struct {
		PeakAlive int `json:"peak_alive"`
		Forks     int `json:"forks"`
	} `json:"processes"`
	Net map[string]any `json:"net"`
}

// CostRecord is the optional per-session cost record.
type CostRecord struct {
	StartupS     *float64 `json:"startup_s"`
	DrainS       *float64 `json:"drain_s"`
	WatchCPUS    *float64 `json:"watch_cpu_s"`
	WatchMaxRSSK *float64 `json:"watch_maxrss_kb"`
}

// Annotation is what only the operator can record about a run: that the user
// intervened (X6), that a harness error not visible in the manifest happened
// (X4: for example a watch failure read from its log), or that the agent did
// not complete the task (reported per task, never an exclusion from H3).
type Annotation struct {
	X4        string `json:"x4,omitempty"`
	X6        string `json:"x6,omitempty"`
	Completed *bool  `json:"completed,omitempty"`
}

// Annotations is annotations.json at the campaign root: run directory
// (relative to the campaign directory) to annotation.
type Annotations struct {
	Runs map[string]Annotation `json:"runs"`
}

// Campaign is a loaded campaign directory.
type Campaign struct {
	Dir            string
	Manifest       Manifest
	ManifestSHA256 string
	Annotations    Annotations
	// FailedAttempts maps a run's relative directory to the number of earlier
	// attempts the runner moved aside (run-NN.failed-<time>).
	FailedAttempts map[string]int
}

// LoadCampaign reads manifest.json and, when present, annotations.json.
func LoadCampaign(dir string) (*Campaign, error) {
	path := filepath.Join(dir, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read campaign manifest: %w", err)
	}
	c := &Campaign{Dir: dir, FailedAttempts: map[string]int{}}
	if err := json.Unmarshal(data, &c.Manifest); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	c.ManifestSHA256 = hex.EncodeToString(sum[:])
	if ad, err := os.ReadFile(filepath.Join(dir, "annotations.json")); err == nil {
		if err := json.Unmarshal(ad, &c.Annotations); err != nil {
			return nil, fmt.Errorf("parse annotations.json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	for i := range c.Manifest.Runs {
		r := &c.Manifest.Runs[i]
		resolved := c.resolve(r.Dir)
		c.FailedAttempts[c.relID(resolved)] = countMovedAside(resolved)
	}
	sort.SliceStable(c.Manifest.Runs, func(i, j int) bool { return runLess(c.Manifest.Runs[i], c.Manifest.Runs[j]) })
	return c, nil
}

func runLess(a, b RunRecord) bool {
	if a.Agent != b.Agent {
		return a.Agent < b.Agent
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.Task != b.Task {
		return a.Task < b.Task
	}
	if a.Mode != b.Mode {
		return a.Mode < b.Mode
	}
	return a.Run < b.Run
}

var movedAside = regexp.MustCompile(`^run-\d+\.failed-`)

func countMovedAside(runDir string) int {
	parent := filepath.Dir(runDir)
	base := filepath.Base(runDir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && movedAside.MatchString(e.Name()) && strings.HasPrefix(e.Name(), base+".failed-") {
			n++
		}
	}
	return n
}

// resolve turns a path the manifest recorded into one that exists. A run
// directory is always <agent>-<version>/<task>/run-NN under the campaign
// directory, so the last three components joined to it win when that exists
// (a campaign that was copied or archived), then the path as written, and
// otherwise the joined path, where the runner would have put it.
func (c *Campaign) resolve(p string) string {
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		return filepath.Join(c.Dir, p)
	}
	parts := strings.Split(filepath.ToSlash(filepath.Clean(p)), "/")
	keep := min(3, len(parts)-1)
	cand := filepath.Join(append([]string{c.Dir}, parts[len(parts)-keep:]...)...)
	if _, err := os.Stat(cand); err == nil {
		return cand
	}
	if _, err := os.Stat(p); err == nil {
		return filepath.Clean(p)
	}
	return cand
}

// relID is a run directory relative to the campaign directory, the identifier
// every list in the results uses.
func (c *Campaign) relID(resolved string) string {
	if rel, err := filepath.Rel(c.Dir, resolved); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(resolved)
}

// RunDir is the resolved directory of a run, and ID its identifier.
func (c *Campaign) RunDir(r RunRecord) string { return c.resolve(r.Dir) }

// ID is the run's identifier.
func (c *Campaign) ID(r RunRecord) string { return c.relID(c.resolve(r.Dir)) }

// ControlsDir is where the run's control runs live: its own directory when it
// took them, else the directory controls.from names.
func (c *Campaign) ControlsDir(r RunRecord) string {
	if !r.Controls.Taken && r.Controls.From != "" {
		return c.resolve(r.Controls.From)
	}
	return c.resolve(r.Dir)
}

// SlotKey identifies a slot: the position a run fills, shared with the
// attempts moved aside from it.
func SlotKey(r RunRecord) string {
	return strings.Join([]string{r.Agent, r.Version, r.Task, r.Mode, strconv.Itoa(r.Run)}, "|")
}
