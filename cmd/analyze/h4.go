package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
)

// H4: overhead (protocol section 4 and 7). H4a reads the synthetic
// benchmark's results.json (scripts/bench-overhead.sh) against the limits of
// decision D3; H4b summarises the real sessions of the campaign.

// BenchSample is one measured run of the benchmark's samples.
type BenchSample struct {
	Scope         string   `json:"scope"`
	Workload      string   `json:"workload"`
	Size          *int     `json:"size"`
	Condition     string   `json:"condition"`
	Rep           int      `json:"rep"`
	OK            bool     `json:"ok"`
	WorkloadWallS *float64 `json:"workload_wall_s"`
	WorkloadCPUS  *float64 `json:"workload_cpu_s"`
	StartupS      *float64 `json:"startup_s"`
	DrainS        *float64 `json:"drain_s"`
	WatchCPUS     *float64 `json:"watch_cpu_s"`
	TreeMaxRSSKB  *float64 `json:"tree_maxrss_kb"`
	GTBytes       *float64 `json:"gt_bytes"`
	GTEvents      *float64 `json:"gt_events"`
	BytesPerEvent *float64 `json:"bytes_per_event"`
	CapEvents     *float64 `json:"capability_events"`
	CapBytes      *float64 `json:"capability_bytes"`
	Complete      *bool    `json:"complete"`
}

type benchFile struct {
	Schema  int            `json:"schema"`
	Machine map[string]any `json:"machine"`
	Params  map[string]any `json:"params"`
	Samples []BenchSample  `json:"samples"`
}

// BenchRow is the H4a numbers of one workload under one condition.
type BenchRow struct {
	Name      string `json:"name"`
	Condition string `json:"condition"`
	Runs      int    `json:"runs"`
	OK        int    `json:"ok"`
	Failed    int    `json:"failed"`
	// WithLoss counts ok runs whose capture verify judged incomplete.
	WithLoss  int      `json:"with_loss"`
	WallRatio *Summary `json:"wall_ratio,omitempty"`
	// WallRatioCI is the bootstrap 95% interval of the median ratio.
	WallRatioCI *Interval `json:"wall_ratio_median_bootstrap95,omitempty"`
	CPURatio    *Summary  `json:"cpu_ratio,omitempty"`
	FixedCostS  *Summary  `json:"fixed_cost_s,omitempty"`
	WatchCPUS   *Summary  `json:"watch_cpu_s,omitempty"`
	PeakRSSMiB  *Summary  `json:"peak_rss_mib,omitempty"`
	CaptureB    *Summary  `json:"capture_bytes,omitempty"`
	BytesPerEv  *Summary  `json:"bytes_per_event,omitempty"`
	CapBytes    *Summary  `json:"capability_bytes,omitempty"`
}

// BenchRun is one labelled benchmark run (for example tmpfs and disk, or
// before and after the campaign).
type BenchRun struct {
	Label   string         `json:"label"`
	Path    string         `json:"path"`
	Machine map[string]any `json:"machine,omitempty"`
	Params  map[string]any `json:"params,omitempty"`
	Rows    []BenchRow     `json:"rows"`
	Limits  []LimitResult  `json:"limits"`
	// Drift is the change in the median wall ratio from this run to the
	// matching run of --overhead-after, per row.
	Drift []Drift `json:"drift,omitempty"`
}

// Drift is machine drift between two runs of one benchmark.
type Drift struct {
	Name      string  `json:"name"`
	Condition string  `json:"condition"`
	Before    float64 `json:"median_wall_ratio_before"`
	After     float64 `json:"median_wall_ratio_after"`
	Change    float64 `json:"change"`
}

// LimitResult is one D3 limit against a benchmark run.
type LimitResult struct {
	ID     string `json:"id"`
	Limit  string `json:"limit"`
	Result string `json:"result"`
	Detail string `json:"detail"`
}

func benchName(s BenchSample) string {
	if s.Size == nil {
		return s.Workload
	}
	return fmt.Sprintf("%s-%d", s.Workload, *s.Size)
}

func val(p *float64) (float64, bool) {
	if p == nil || math.IsNaN(*p) {
		return 0, false
	}
	return *p, true
}

// LoadBench reads one benchmark results.json and computes H4a's rows and the
// D3 verdicts. Repetition 0 is the warm-up and is left out, as in the
// benchmark's own summary. Ratios pair each run under watch with the same
// workload alone in the same repetition.
func LoadBench(label, path string) (*BenchRun, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the overhead benchmark: %w", err)
	}
	var f benchFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	run := &BenchRun{Label: label, Path: path, Machine: f.Machine, Params: f.Params}
	type key struct {
		name string
		rep  int
	}
	alone := map[key]BenchSample{}
	for _, s := range f.Samples {
		if s.Scope == "workload" && s.Condition == "alone" && s.OK && s.Rep > 0 {
			alone[key{benchName(s), s.Rep}] = s
		}
	}
	type gk struct{ name, cond string }
	groups := map[gk][]BenchSample{}
	for _, s := range f.Samples {
		if s.Scope != "workload" || s.Rep == 0 {
			continue
		}
		groups[gk{benchName(s), s.Condition}] = append(groups[gk{benchName(s), s.Condition}], s)
	}
	keys := make([]gk, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	order := map[string]int{"alone": 0, "all": 1, "fs": 2, "proc": 3, "net": 4}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return order[keys[i].cond] < order[keys[j].cond]
	})
	for _, k := range keys {
		row := BenchRow{Name: k.name, Condition: k.cond}
		var wall, cpu, fixed, wcpu, rss, capture, bpe, capb []float64
		for _, s := range groups[k] {
			row.Runs++
			if !s.OK {
				row.Failed++
				continue
			}
			row.OK++
			if s.Complete != nil && !*s.Complete {
				row.WithLoss++
			}
			if a, ok := alone[key{k.name, s.Rep}]; ok && k.cond != "alone" {
				if w, ok1 := val(s.WorkloadWallS); ok1 {
					if aw, ok2 := val(a.WorkloadWallS); ok2 && aw > 0 {
						wall = append(wall, w/aw)
					}
				}
				if c, ok1 := val(s.WorkloadCPUS); ok1 {
					if ac, ok2 := val(a.WorkloadCPUS); ok2 && ac > 0 {
						cpu = append(cpu, c/ac)
					}
				}
			}
			if su, ok1 := val(s.StartupS); ok1 {
				if dr, ok2 := val(s.DrainS); ok2 && k.cond != "alone" {
					fixed = append(fixed, su+dr)
				}
			}
			appendVal := func(dst *[]float64, p *float64, scale float64) {
				if v, ok := val(p); ok {
					*dst = append(*dst, v*scale)
				}
			}
			if k.cond != "alone" {
				appendVal(&wcpu, s.WatchCPUS, 1)
				appendVal(&capture, s.GTBytes, 1)
				appendVal(&bpe, s.BytesPerEvent, 1)
				appendVal(&capb, s.CapBytes, 1)
			}
			appendVal(&rss, s.TreeMaxRSSKB, 1.0/1024)
		}
		set := func(dst **Summary, v []float64) {
			if s, ok := Summarize(v); ok {
				*dst = &s
			}
		}
		set(&row.WallRatio, wall)
		set(&row.CPURatio, cpu)
		set(&row.FixedCostS, fixed)
		set(&row.WatchCPUS, wcpu)
		set(&row.PeakRSSMiB, rss)
		set(&row.CaptureB, capture)
		set(&row.BytesPerEv, bpe)
		set(&row.CapBytes, capb)
		if ci, ok := BootstrapMedian(wall, BootstrapResamples, BootstrapSeed); ok {
			row.WallRatioCI = &ci
		}
		run.Rows = append(run.Rows, row)
	}
	run.Limits = judgeBench(run)
	return run, nil
}

func (r *BenchRun) row(name, cond string) *BenchRow {
	for i := range r.Rows {
		if r.Rows[i].Name == name && r.Rows[i].Condition == cond {
			return &r.Rows[i]
		}
	}
	return nil
}

// judgeBench applies the D3 limits to the condition `all`.
func judgeBench(r *BenchRun) []LimitResult {
	var out []LimitResult
	// Wall ratio on the named workloads.
	lim := LimitResult{ID: "H4a-wall", Limit: fmt.Sprintf("median wall ratio at most %.2f on %s under %s", MaxWallRatio, strings.Join(WallRatioWorkloads, " and "), H4Condition)}
	var parts []string
	worst, missing, over := 0.0, 0, 0
	for _, name := range WallRatioWorkloads {
		row := r.row(name, H4Condition)
		if row == nil || row.WallRatio == nil {
			missing++
			parts = append(parts, name+": no data")
			continue
		}
		m := row.WallRatio.Median
		parts = append(parts, fmt.Sprintf("%s: median %.3f", name, m))
		worst = math.Max(worst, m)
		if m > MaxWallRatio {
			over++
		}
	}
	lim.Detail = strings.Join(parts, "; ")
	switch {
	case over > 0:
		lim.Result = "REFUTED"
	case missing > 0:
		lim.Result = "NOT EVALUATED"
	default:
		lim.Result = "HOLDS"
	}
	out = append(out, lim)

	// The other three limits are read over every workload under `all`.
	fixed := LimitResult{ID: "H4a-fixed-cost", Limit: fmt.Sprintf("fixed cost (start-up plus drain) at most %.0f s per session under %s, on every workload", MaxFixedCostSeconds, H4Condition)}
	rss := LimitResult{ID: "H4a-rss", Limit: fmt.Sprintf("peak RSS of the watch tree at most %.0f MiB under %s, on every workload", MaxWatchRSSMiB, H4Condition)}
	loss := LimitResult{ID: "H4a-loss", Limit: fmt.Sprintf("zero runs with loss under %s, on every workload", H4Condition)}
	var fixedMax, rssMax float64
	lossRuns, failed, seen := 0, 0, 0
	for _, row := range r.Rows {
		if row.Condition != H4Condition {
			continue
		}
		seen++
		lossRuns += row.WithLoss
		failed += row.Failed
		if row.FixedCostS != nil {
			fixedMax = math.Max(fixedMax, row.FixedCostS.Median)
		}
		if row.PeakRSSMiB != nil {
			rssMax = math.Max(rssMax, row.PeakRSSMiB.Top1)
		}
	}
	if seen == 0 {
		for _, l := range []*LimitResult{&fixed, &rss, &loss} {
			l.Result, l.Detail = "NOT EVALUATED", "no run under "+H4Condition
		}
	} else {
		fixed.Detail = fmt.Sprintf("largest per-workload median %.3f s", fixedMax)
		fixed.Result = passFail(fixedMax <= MaxFixedCostSeconds)
		rss.Detail = fmt.Sprintf("largest observed peak %.1f MiB (top1 over the repetitions)", rssMax)
		rss.Result = passFail(rssMax <= MaxWatchRSSMiB)
		loss.Detail = fmt.Sprintf("%d run(s) with loss; %d run(s) failed and are not counted as clean", lossRuns, failed)
		loss.Result = passFail(lossRuns <= MaxLossRuns)
	}
	return append(out, fixed, rss, loss)
}

func passFail(ok bool) string {
	if ok {
		return "HOLDS"
	}
	return "REFUTED"
}

// AddDrift computes the drift of this run against the same benchmark run
// repeated after the campaign.
func (r *BenchRun) AddDrift(after *BenchRun) {
	for _, row := range r.Rows {
		a := after.row(row.Name, row.Condition)
		if a == nil || row.WallRatio == nil || a.WallRatio == nil {
			continue
		}
		r.Drift = append(r.Drift, Drift{Name: row.Name, Condition: row.Condition, Before: row.WallRatio.Median, After: a.WallRatio.Median, Change: a.WallRatio.Median - row.WallRatio.Median})
	}
}

// AgentCost is the H4b summary of one agent version's real sessions: per
// session and per claim. Fields the manifest or logs do not carry are
// counted as not measured.
type AgentCost struct {
	AgentVersion
	Sessions int `json:"sessions"`
	// Per-session summaries (median, quartiles, top1).
	DurationS        *Summary `json:"duration_s,omitempty"`
	Events           *Summary `json:"events,omitempty"`
	Claims           *Summary `json:"claims,omitempty"`
	PeakProcesses    *Summary `json:"peak_processes,omitempty"`
	CaptureBytes     *Summary `json:"capture_bytes,omitempty"`
	BytesPerEvent    *Summary `json:"bytes_per_event,omitempty"`
	CapabilityEvents *Summary `json:"capability_events,omitempty"`
	CapabilityBytes  *Summary `json:"capability_bytes,omitempty"`
	StartupS         *Summary `json:"startup_s,omitempty"`
	DrainS           *Summary `json:"drain_s,omitempty"`
	WatchCPUS        *Summary `json:"watch_cpu_s,omitempty"`
	WatchMaxRSSKB    *Summary `json:"watch_maxrss_kb,omitempty"`
	// Per-claim summaries.
	EventsPerClaim       *Summary `json:"events_per_claim,omitempty"`
	CaptureBytesPerClaim *Summary `json:"capture_bytes_per_claim,omitempty"`
	DurationPerClaimS    *Summary `json:"duration_s_per_claim,omitempty"`
	// NotMeasured counts the sessions lacking each field, by field.
	NotMeasured map[string]int `json:"not_measured,omitempty"`
}

// BuildH4b summarises the real sessions per agent version: the sessions of
// every completed run (X3, X4, X6 excluded).
func BuildH4b(runs []RunOutput) []AgentCost {
	var out []AgentCost
	for _, av := range agentVersions(runs) {
		c := AgentCost{AgentVersion: av, NotMeasured: map[string]int{}}
		cols := map[string][]float64{}
		add := func(name string, v *float64) {
			if v == nil {
				c.NotMeasured[name]++
				return
			}
			cols[name] = append(cols[name], *v)
		}
		fi := func(p *int) *float64 {
			if p == nil {
				return nil
			}
			return fptr(float64(*p))
		}
		for _, o := range runs {
			if o.Agent != av.Agent || o.Version != av.Version || !o.Scope.Completed || o.Cost == nil {
				continue
			}
			c.Sessions++
			sc := o.Cost
			add("duration_s", fptr(sc.DurationS))
			add("events", fi(sc.Events))
			add("claims", fptr(float64(sc.Claims)))
			add("peak_processes", fi(sc.PeakProcesses))
			if sc.CaptureBytes != nil {
				add("capture_bytes", fptr(float64(*sc.CaptureBytes)))
			} else {
				add("capture_bytes", nil)
			}
			add("bytes_per_event", sc.BytesPerEvent)
			add("capability_events", fi(sc.CapabilityEvents))
			add("capability_bytes", fi(sc.CapabilityBytes))
			add("startup_s", sc.StartupS)
			add("drain_s", sc.DrainS)
			add("watch_cpu_s", sc.WatchCPUS)
			add("watch_maxrss_kb", sc.WatchMaxRSSKB)
			if sc.Claims > 0 {
				per := float64(sc.Claims)
				if sc.Events != nil {
					cols["events_per_claim"] = append(cols["events_per_claim"], float64(*sc.Events)/per)
				}
				if sc.CaptureBytes != nil {
					cols["capture_bytes_per_claim"] = append(cols["capture_bytes_per_claim"], float64(*sc.CaptureBytes)/per)
				}
				cols["duration_s_per_claim"] = append(cols["duration_s_per_claim"], sc.DurationS/per)
			}
		}
		sum := func(name string) *Summary {
			if s, ok := Summarize(cols[name]); ok {
				return &s
			}
			return nil
		}
		c.DurationS, c.Events, c.Claims, c.PeakProcesses = sum("duration_s"), sum("events"), sum("claims"), sum("peak_processes")
		c.CaptureBytes, c.BytesPerEvent = sum("capture_bytes"), sum("bytes_per_event")
		c.CapabilityEvents, c.CapabilityBytes = sum("capability_events"), sum("capability_bytes")
		c.StartupS, c.DrainS, c.WatchCPUS, c.WatchMaxRSSKB = sum("startup_s"), sum("drain_s"), sum("watch_cpu_s"), sum("watch_maxrss_kb")
		c.EventsPerClaim, c.CaptureBytesPerClaim, c.DurationPerClaimS = sum("events_per_claim"), sum("capture_bytes_per_claim"), sum("duration_s_per_claim")
		if len(c.NotMeasured) == 0 {
			c.NotMeasured = nil
		}
		out = append(out, c)
	}
	return out
}

// H4Results is the H4 section.
type H4Results struct {
	Bench []BenchRun  `json:"h4a_benchmarks,omitempty"`
	Real  []AgentCost `json:"h4b_real_sessions"`
}
