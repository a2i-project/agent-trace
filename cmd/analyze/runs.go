package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/config"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// RunOutput is everything computed about one manifest run. It holds
// summaries only: the raw session is released once the run is processed.
type RunOutput struct {
	ID      string `json:"id"`
	Agent   string `json:"agent"`
	Version string `json:"version"`
	Task    string `json:"task"`
	Mode    string `json:"mode,omitempty"`
	Status  string `json:"status"`
	// Exclusions lists every rule of protocol 10.1 that applies. Scope says
	// what that leaves in.
	Exclusions []Exclusion `json:"exclusions,omitempty"`
	Scope      Scope       `json:"scope"`
	LoadError  string      `json:"load_error,omitempty"`
	Claims     int         `json:"claims"`
	// Completed is the annotation's word on task completion (nil: not said).
	Completed *bool `json:"completed,omitempty"`
	// Controls the baseline was built from, and those dropped for loss (X2).
	ControlsUsed    int      `json:"controls_used"`
	ControlsDropped int      `json:"controls_dropped"`
	DroppedReasons  []string `json:"controls_dropped_reasons,omitempty"`
	ControlTools    string   `json:"control_tools,omitempty"`
	StrictReason    string   `json:"version_reason,omitempty"`
	// Primary is the H3 verdict at the primary agreement; Sensitivity holds
	// the same at each grid setting and leave-one-out, keyed by setting label.
	Primary     *H3Run            `json:"primary,omitempty"`
	Sensitivity map[string]*H3Run `json:"sensitivity,omitempty"`
	// Surfaces is the attack surface (protocol 5.6) per setting ("primary", the grid
	// labels, "loo").
	Surfaces map[string]Surface `json:"surfaces,omitempty"`
	// Recorded is the runner's own verdict with the baseline, and
	// RunnerAgrees whether this command's outcome equals it.
	Recorded     *RecordedVerdict `json:"runner_verdict,omitempty"`
	RunnerAgrees *bool            `json:"runner_outcome_agrees,omitempty"`
	// SweepExclusion is X5's set-aside of the run from the attack sweep.
	SweepExclusion *Exclusion   `json:"sweep_exclusion,omitempty"`
	Attack         *AttackRun   `json:"attack,omitempty"`
	Cost           *SessionCost `json:"cost,omitempty"`
	// LOONote says why leave-one-out was not computed.
	LOONote string `json:"loo_note,omitempty"`
}

// SessionCost is the H4b record of one session: what the manifest, the
// capture file and the runner's own verify output give. A nil field was not
// measured.
type SessionCost struct {
	DurationS        float64  `json:"duration_s"`
	Events           *int     `json:"events"`
	Claims           int      `json:"claims"`
	PeakProcesses    *int     `json:"peak_processes"`
	CaptureBytes     *int64   `json:"capture_bytes"`
	BytesPerEvent    *float64 `json:"bytes_per_event"`
	CapabilityEvents *int     `json:"capability_events"`
	CapabilityBytes  *int     `json:"capability_bytes"`
	StartupS         *float64 `json:"startup_s"`
	DrainS           *float64 `json:"drain_s"`
	WatchCPUS        *float64 `json:"watch_cpu_s"`
	WatchMaxRSSKB    *float64 `json:"watch_maxrss_kb"`
}

// Settings of the sensitivity analysis.
const (
	SettingPrimary = "primary"
	SettingLOO     = "loo"
)

// Pools holds the control captures of every run, grouped by agent, version
// and control tool set, for the leave-one-out baseline: each run's pooled
// baseline is built from the controls of every other capture of its pool.
type Pools struct {
	mu    sync.Mutex
	pools map[string]*pool
	c     *Campaign
}

type pool struct {
	once sync.Once
	// dirs maps a controls directory to its usable controls.
	dirs map[string][]models.GroundTruthFile
}

// NewPools prepares the pools of a campaign. Controls load on first use.
func NewPools(c *Campaign) *Pools { return &Pools{pools: map[string]*pool{}, c: c} }

func poolKey(agentName, version, tools string) string {
	return strings.Join([]string{agentName, version, tools}, "|")
}

// controlTools reads the control task's recorded tool set in a directory.
func controlTools(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "control-tools.txt"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (p *Pools) get(r RunRecord, tools string) *pool {
	key := poolKey(r.Agent, r.Version, tools)
	p.mu.Lock()
	pl := p.pools[key]
	if pl == nil {
		pl = &pool{}
		p.pools[key] = pl
	}
	p.mu.Unlock()
	pl.once.Do(func() {
		pl.dirs = map[string][]models.GroundTruthFile{}
		for _, o := range p.c.Manifest.Runs {
			if o.Agent != r.Agent || o.Version != r.Version || o.Status != "ok" {
				continue
			}
			dir := p.c.ControlsDir(o)
			if _, seen := pl.dirs[dir]; seen || controlTools(dir) != tools {
				continue
			}
			kept, _ := LoadControls(ControlPaths(dir))
			pl.dirs[dir] = kept
		}
	})
	return pl
}

// Others returns the controls of every capture of the run's pool except the
// run's own controls directory, in directory order.
func (p *Pools) Others(s *Session) []models.GroundTruthFile {
	pl := p.get(s.Rec, s.ControlTools)
	var dirs []string
	for d := range pl.dirs {
		if d != s.ControlsDir {
			dirs = append(dirs, d)
		}
	}
	sort.Strings(dirs)
	var out []models.GroundTruthFile
	for _, d := range dirs {
		out = append(out, pl.dirs[d]...)
	}
	return out
}

// ProcessOptions are the switches of the per-run pipeline.
type ProcessOptions struct {
	Config      *config.Config
	Sweep       bool
	SweepOpts   SweepOptions
	Sensitivity bool
	LOO         bool
	Pools       *Pools
}

// ProcessRun loads one run and computes everything the per-run analyses read.
func ProcessRun(c *Campaign, rec RunRecord, o ProcessOptions) RunOutput {
	id := c.ID(rec)
	ann := c.Annotations.Runs[id]
	out := RunOutput{ID: id, Agent: rec.Agent, Version: rec.Version, Task: rec.Task, Mode: rec.Mode, Status: rec.Status, Completed: ann.Completed, Recorded: rec.Verdict.WithBaseline}
	s, err := LoadSession(c, rec)
	if err != nil {
		// A message names files by their path under the campaign directory.
		err = errors.New(strings.ReplaceAll(err.Error(), filepath.Clean(c.Dir)+string(os.PathSeparator), ""))
		out.LoadError = err.Error()
	}
	if s == nil {
		s = &Session{Rec: rec}
	}
	out.Claims = len(s.Claims)
	out.Exclusions = Exclusions(s.Facts(ann, err))
	out.Scope = ScopeOf(out.Exclusions)
	out.Cost = c.sessionCost(rec, s)
	if err != nil {
		return out
	}
	out.ControlsUsed, out.ControlsDropped, out.DroppedReasons, out.ControlTools = len(s.Controls), s.ControlsDropped, s.DroppedReasons, s.ControlTools
	if o.Config != nil {
		out.StrictReason = versionReason(o.Config, rec.Agent, s.Version)
	}
	loss := hasRule(out.Exclusions, X1)

	primary, baseline := primaryOf(s, out.StrictReason, loss)
	out.Primary = primary
	if primary.Error == "" && out.Recorded != nil {
		agrees := out.Recorded.Outcome == primary.Outcome
		out.RunnerAgrees = &agrees
	}
	if baseline == nil || !out.Scope.Completed {
		return out
	}
	out.Surfaces = map[string]Surface{}
	sf, _, _ := s.SurfaceOf(baseline)
	out.Surfaces[SettingPrimary] = sf
	if o.Sensitivity {
		out.Sensitivity = map[string]*H3Run{}
		for _, a := range AgreementGrid {
			if a.Value == PrimaryAgreement {
				out.Sensitivity[a.Label] = primary
				out.Surfaces[a.Label] = sf
				continue
			}
			b, err := BuildBaseline(s.Adapter, s.Version, s.Controls, a.Value)
			if err != nil {
				out.Sensitivity[a.Label] = &H3Run{Error: err.Error()}
				continue
			}
			out.Sensitivity[a.Label] = s.Honest(b, out.StrictReason, loss)
			out.Surfaces[a.Label], _, _ = s.SurfaceOf(b)
		}
		if o.LOO && o.Pools != nil {
			others := o.Pools.Others(s)
			if len(others) == 0 {
				out.LOONote = "no other capture of the same agent, version and control tool set"
			} else if b, err := BuildBaseline(s.Adapter, s.Version, others, PrimaryAgreement); err != nil {
				out.Sensitivity[SettingLOO] = &H3Run{Error: err.Error()}
			} else {
				out.Sensitivity[SettingLOO] = s.Honest(b, out.StrictReason, loss)
				out.Surfaces[SettingLOO], _, _ = s.SurfaceOf(b)
			}
		}
	}
	if o.Sweep && out.Scope.Kept {
		if ex, skip := H2Excluded(len(s.Claims)); skip {
			out.SweepExclusion = &ex
		} else {
			out.Attack = s.Sweep(baseline, o.SweepOpts)
		}
	}
	return out
}

// primaryOf builds the primary baseline and the honest verdict with it.
func primaryOf(s *Session, strict string, loss bool) (*H3Run, *agent.Baseline) {
	if len(s.Controls) == 0 {
		return &H3Run{Error: "no usable control run"}, nil
	}
	b, err := BuildBaseline(s.Adapter, s.Version, s.Controls, PrimaryAgreement)
	if err != nil {
		return &H3Run{Error: err.Error()}, nil
	}
	return s.Honest(b, strict, loss), b
}

// sessionCost reads what the manifest, the capture file and the runner's
// verify output say about a session's cost (H4b).
func (c *Campaign) sessionCost(rec RunRecord, s *Session) *SessionCost {
	sc := &SessionCost{DurationS: rec.DurationS, Claims: len(s.Claims)}
	if rec.Scale != nil {
		ev, pk := rec.Scale.Events.Total, rec.Scale.Processes.PeakAlive
		sc.Events, sc.PeakProcesses = &ev, &pk
	}
	dir := c.RunDir(rec)
	if st, err := os.Stat(filepath.Join(dir, groundTruthName(rec))); err == nil {
		n := st.Size()
		sc.CaptureBytes = &n
		if sc.Events != nil && *sc.Events > 0 {
			bpe := float64(n) / float64(*sc.Events)
			sc.BytesPerEvent = &bpe
		}
	}
	if ev, by, ok := capabilityRecord(filepath.Join(dir, "verify-baseline.json")); ok {
		sc.CapabilityEvents, sc.CapabilityBytes = &ev, &by
	}
	if rec.Cost != nil {
		sc.StartupS, sc.DrainS, sc.WatchCPUS, sc.WatchMaxRSSKB = rec.Cost.StartupS, rec.Cost.DrainS, rec.Cost.WatchCPUS, rec.Cost.WatchMaxRSSK
	}
	return sc
}

// capabilityRecord counts the events retained beneath commands in verify's
// JSON report and their size as compact JSON, as scripts/bench-overhead.sh
// measures the capability record.
func capabilityRecord(path string) (events, bytesN int, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	var rep struct {
		Commands []struct {
			Events []json.RawMessage `json:"events"`
		} `json:"commands"`
	}
	if json.Unmarshal(data, &rep) != nil {
		return 0, 0, false
	}
	size := 2 // the enclosing brackets
	for _, c := range rep.Commands {
		for _, e := range c.Events {
			var buf bytes.Buffer
			if json.Compact(&buf, e) != nil {
				continue
			}
			if events > 0 {
				size++ // the comma
			}
			size += buf.Len()
			events++
		}
	}
	if events == 0 {
		size = 2
	}
	return events, size, true
}

// ParallelMap applies f to each index of 0..n-1 with at most jobs workers and
// returns the results in index order, so output does not depend on scheduling.
func ParallelMap[T any](n, jobs int, f func(i int) T) []T {
	out := make([]T, n)
	if jobs < 1 {
		jobs = 1
	}
	idx := make(chan int)
	var wg sync.WaitGroup
	for range min(jobs, max(n, 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				out[i] = f(i)
			}
		}()
	}
	for i := range n {
		idx <- i
	}
	close(idx)
	wg.Wait()
	return out
}
