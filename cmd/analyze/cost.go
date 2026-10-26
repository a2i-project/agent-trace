package main

import (
	"syscall"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
)

// CostRow is the in-process timing of one run: building its baseline and
// verifying it with and without the baseline. The timings vary between runs of
// the command, so they are written to a file of their own and never to
// results.json. Peak resident set is not measured: it is a property of the
// whole process and no run's alone.
type CostRow struct {
	Run                 string  `json:"run"`
	Claims              int     `json:"claims"`
	Events              int     `json:"events"`
	Controls            int     `json:"controls"`
	BaselineWallS       float64 `json:"baseline_wall_s"`
	BaselineCPUS        float64 `json:"baseline_cpu_s"`
	VerifyWallS         float64 `json:"verify_wall_s"`
	VerifyCPUS          float64 `json:"verify_cpu_s"`
	VerifyBaselineWallS float64 `json:"verify_with_baseline_wall_s"`
	VerifyBaselineCPUS  float64 `json:"verify_with_baseline_cpu_s"`
	Error               string  `json:"error,omitempty"`
}

func cpuSeconds() float64 {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6 + float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
}

// timed runs f and returns its wall and CPU seconds.
func timed(f func()) (wall, cpu float64) {
	c0, t0 := cpuSeconds(), time.Now()
	f()
	return time.Since(t0).Seconds(), cpuSeconds() - c0
}

// measureCost times each run sequentially, so the process-wide CPU counter
// belongs to one run at a time, and writes the rows to path.
func measureCost(path string, c *Campaign) error {
	var rows []CostRow
	for _, rec := range c.Manifest.Runs {
		s, err := LoadSession(c, rec)
		if err != nil {
			rows = append(rows, CostRow{Run: c.ID(rec), Error: err.Error()})
			continue
		}
		row := CostRow{Run: s.ID, Claims: len(s.Claims), Events: len(s.G.Events), Controls: len(s.Controls)}
		row.VerifyWallS, row.VerifyCPUS = timed(func() { _ = s.verify(s.Claims, nil) })
		if len(s.Controls) > 0 {
			var b *agent.Baseline
			var berr error
			row.BaselineWallS, row.BaselineCPUS = timed(func() { b, berr = BuildBaseline(s.Adapter, s.Version, s.Controls, PrimaryAgreement) })
			if berr != nil {
				row.Error = berr.Error()
			} else {
				row.VerifyBaselineWallS, row.VerifyBaselineCPUS = timed(func() { _ = s.verify(s.Claims, b) })
			}
		}
		rows = append(rows, row)
	}
	return writeJSON(path, struct {
		Note string    `json:"note"`
		Rows []CostRow `json:"rows"`
	}{"in-process timings of baseline building and verification, one run at a time; they vary between invocations and are not part of results.json", rows})
}
