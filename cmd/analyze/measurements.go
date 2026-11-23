package main

import (
	"fmt"
	"strings"
)

// Measurement states. A measurement line states what was measured and its
// value, never whether it meets a target: the analysis holds none (E-11).
const (
	// Measured: the value line gives the numbers.
	Measured = "MEASURED"
	// NotMeasured: nothing in the inputs measures it; the value line says why.
	NotMeasured = "NOT MEASURED"
	// Unjudged: the numbers exist but a control did not behave as
	// registered, so they do not measure what the line names (H1).
	Unjudged = "UNJUDGED"
)

// Measurement is one line of the report's measurement table: what is
// measured, over which scope, and its value with interval and counts.
type Measurement struct {
	ID      string `json:"id"`
	Scope   string `json:"scope,omitempty"`
	Measure string `json:"measure"`
	State   string `json:"state"`
	Value   string `json:"value"`
}

func pct(p *float64) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100**p)
}

// threeCounts renders considered, evaluated and succeeded.
func threeCounts(r Rate) string {
	s := fmt.Sprintf("considered %d, evaluated %d, succeeded %d", r.Considered, r.Evaluated, r.Succeeded)
	if len(r.NotEvaluated) > 0 {
		var parts []string
		for _, k := range sortedKeys(r.NotEvaluated) {
			parts = append(parts, fmt.Sprintf("%s: %d", k, r.NotEvaluated[k]))
		}
		s += "; not evaluated (" + strings.Join(parts, ", ") + ")"
	}
	return s
}

func interval(i *Interval) string {
	if i == nil {
		return "n/a"
	}
	return fmt.Sprintf("[%.3f, %.3f]", i.Lo, i.Hi)
}

func exactNote(e *ExactBound) string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("; exact one-sided 95%% %s bound %.3f", e.Kind, e.Value)
}

// crText renders a pooled rate with its bootstrap interval.
func crText(c ClusterRate) string {
	if c.Rate == nil {
		return fmt.Sprintf("%.0f of %.0f (n/a)", c.Num, c.Den)
	}
	return fmt.Sprintf("%.0f of %.0f (%.3f, bootstrap 95%% %s)", c.Num, c.Den, *c.Rate, interval(c.CI))
}

// BuildMeasurements produces one line per measured quantity of protocol
// section 4 (H1 to H4), and the halt conditions: an H2e contradiction and an
// unattributed INCONCLUSIVE, which are defects of the instrument, not
// targets (protocol 10.2).
func BuildMeasurements(res *Results) ([]Measurement, []string) {
	var v []Measurement
	var halts []string
	if res.H1 != nil {
		for _, c := range res.H1.Measures {
			v = append(v, Measurement{ID: c.ID, Scope: c.Row, Measure: c.Measure, State: c.State, Value: c.Value})
		}
	} else {
		v = append(v, Measurement{ID: "H1", Measure: "acceptance of the attacks by the compared tools", State: NotMeasured, Value: "no comparison sweep output was read"})
	}
	if res.H2 != nil {
		var hv []Measurement
		hv, halts = h2Measurements(res)
		v = append(v, hv...)
	} else {
		v = append(v, Measurement{ID: "H2", Measure: "detection, classification and localisation of A1 to A3; A4 counterexamples", State: NotMeasured, Value: "the attack sweep was skipped"})
	}
	h3v, h3halts := h3Measurements(res)
	v = append(v, h3v...)
	halts = append(halts, h3halts...)
	if len(res.H4.Bench) == 0 {
		v = append(v, Measurement{ID: "H4a", Measure: "overhead of instrumentation and verification on synthetic workloads", State: NotMeasured, Value: "no benchmark results.json was read"})
	}
	for _, b := range res.H4.Bench {
		for _, l := range b.Summary {
			v = append(v, Measurement{ID: l.ID, Scope: "run " + b.Label, Measure: l.Measure, State: l.State, Value: l.Value})
		}
	}
	v = append(v, Measurement{ID: "H4b", Measure: "real-session costs", State: Measured, Value: fmt.Sprintf("%d agent version(s) summarised per session and per claim", len(res.H4.Real))})
	return v, halts
}

func h3Measurements(res *Results) ([]Measurement, []string) {
	var v []Measurement
	var halts []string
	for _, av := range agentVersions2(res.H3) {
		scopes := []string{ScopeAll}
		if res.H3.Cell(av, ScopeHeldOut) != nil {
			scopes = append(scopes, ScopeHeldOut)
		}
		for _, scope := range scopes {
			cell := res.H3.Cell(av, scope)
			label := fmt.Sprintf("%s %s, %s", av.Agent, av.Version, scope)
			a := cell.RunFP
			fp := Measurement{ID: "H3a", Scope: label, Measure: "per-run false-positive rate over kept honest runs (runs with Findings() > 0)"}
			if a.Rate == nil {
				fp.State, fp.Value = NotMeasured, threeCounts(a)
			} else {
				fp.State = Measured
				fp.Value = fmt.Sprintf("%d of %d runs (%s), Wilson 95%% %s%s; %s", a.Succeeded, a.Evaluated, pct(a.Rate), interval(a.Wilson), exactNote(a.Exact), threeCounts(a))
			}
			v = append(v, fp)
			cf := cell.ClaimFP
			v = append(v, Measurement{ID: "H3b", Scope: label, Measure: "per-claim false-positive rate", State: Measured,
				Value: fmt.Sprintf("%d of %d claims flagged (%s), bootstrap 95%% %s over %d sessions; per-run counts beside it: unrecorded %d (in %d runs), unexplained subtrees %d (in %d), unexplained sensitive changes %d (in %d)",
					cf.Flagged, cf.Claims, pct(cf.Rate.Rate), interval(cf.Rate.CI), cf.Sessions, cf.Unrecorded, cf.RunsUnrecorded, cf.UnexplainedSubtrees, cf.RunsSubtrees, cf.UnexplainedSensitive, cf.RunsSensitive)})
			inc := cell.Inconclusive
			c3 := Measurement{ID: "H3c", Scope: label, Measure: "INCONCLUSIVE rate over completed honest runs and its causes"}
			if inc.Rate.Rate == nil {
				c3.State, c3.Value = NotMeasured, threeCounts(inc.Rate)
			} else {
				c3.State = Measured
				c3.Value = fmt.Sprintf("%s of %d completed runs INCONCLUSIVE (Wilson 95%% %s); primary causes %s; %s", pct(inc.Rate.Rate), inc.Rate.Evaluated, interval(inc.Rate.Wilson), countsLine(inc.Primary), threeCounts(inc.Rate))
			}
			if len(inc.Unattributed) > 0 {
				c3.Value += fmt.Sprintf("; %d INCONCLUSIVE run(s) with a reason no listed cause matches: %s; the reasons: %s", len(inc.Unattributed), strings.Join(inc.Unattributed, ", "), strings.Join(inc.UnmatchedReasons, " | "))
				halts = append(halts, fmt.Sprintf("H3c (%s): %d INCONCLUSIVE run(s) with a reason that matches no cause of the list: an unattributed INCONCLUSIVE is an instrument defect (%s)", label, len(inc.Unattributed), strings.Join(inc.Unattributed, ", ")))
			}
			v = append(v, c3)
			f := cell.Faithful
			d := Measurement{ID: "H3d", Scope: label, Measure: "FAITHFUL rate over completed honest runs"}
			if f.Rate == nil {
				d.State, d.Value = NotMeasured, threeCounts(f)
			} else {
				d.State, d.Value = Measured, fmt.Sprintf("%d of %d runs (%s), Wilson 95%% %s; %s", f.Succeeded, f.Evaluated, pct(f.Rate), interval(f.Wilson), threeCounts(f))
			}
			v = append(v, d)
		}
	}
	return v, halts
}

func agentVersions2(h *H3Results) []AgentVersion {
	var out []AgentVersion
	seen := map[AgentVersion]bool{}
	for _, c := range h.Cells {
		if !seen[c.AgentVersion] {
			seen[c.AgentVersion] = true
			out = append(out, c.AgentVersion)
		}
	}
	return out
}

func countsLine(m map[string]int) string {
	if len(m) == 0 {
		return "none"
	}
	var parts []string
	for _, k := range sortedKeys(m) {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// primaryRates pools the primary rates of an agent ("" for every agent) over
// its sessions, each session a cluster: detected, classified and located over
// the detectable mutations, then classified and located over the detected
// ones, each with the session bootstrap.
func primaryRates(p *Protocol, runs []RunOutput, agentName string, excludeToolHeavy bool) (overDetectable, overDetected []ClusterRate) {
	var cd, cdet []Cluster
	for _, o := range runs {
		if (agentName != "" && o.Agent != agentName) || o.Attack == nil {
			continue
		}
		if excludeToolHeavy && p.IsToolHeavy(o.Agent, o.Task) {
			continue
		}
		var t Tally
		for _, tl := range o.Attack.Tallies {
			if specOf(tl.Variant).InPrimaryRates() {
				tt := *tl
				t.merge(&tt)
			}
		}
		cd = append(cd, Cluster{Den: float64(t.Detectable), Nums: []float64{float64(t.Detected), float64(t.Classified), float64(t.Located)}})
		cdet = append(cdet, Cluster{Den: float64(t.Detected), Nums: []float64{float64(t.Classified), float64(t.Located)}})
	}
	return ClusterBootstrap(cd, 3, BootstrapResamples, BootstrapSeed), ClusterBootstrap(cdet, 2, BootstrapResamples, BootstrapSeed)
}

func h2Measurements(res *Results) ([]Measurement, []string) {
	h := res.H2
	var v []Measurement
	var halts []string
	note := ""
	if h.Reduced {
		note = fmt.Sprintf(" (REDUCED sweep: seeds %d to %d of the registered %d to %d)", SeedFirst, h.LastSeed, SeedFirst, SeedLast)
	}
	agents := []string{""}
	seen := map[string]bool{}
	for _, c := range h.Cells {
		if !seen[c.Agent] {
			seen[c.Agent] = true
			agents = append(agents, c.Agent)
		}
	}
	for _, a := range agents {
		t := PrimaryPooled(res.protocol, res.Runs, a, false)
		scope := "every agent, every capture"
		if a != "" {
			scope = a
		}
		if t.Detectable == 0 {
			for _, id := range []string{"H2a", "H2b", "H2c"} {
				v = append(v, Measurement{ID: id, Scope: scope, Measure: h2Measure(id), State: NotMeasured, Value: "no detectable in-capture mutation was evaluated" + note})
			}
			continue
		}
		misses := 0
		for _, m := range h.Misses {
			if (a == "" || runAgent(res.Runs, m.Run) == a) && specOf(m.Variant).InPrimaryRates() {
				misses++
			}
		}
		rd, rdet := primaryRates(res.protocol, res.Runs, a, false)
		v = append(v, Measurement{ID: "H2a", Scope: scope, Measure: h2Measure("H2a"), State: Measured,
			Value: fmt.Sprintf("%s detected; %d distinct per-session cases; undetectable by design %d, out of capture %d, unverifiable %d; %d miss(es) listed with their Diagnose records%s", crText(rd[0]), t.Distinct, t.Undetectable, t.OutOfCapture, t.Unverifiable, misses, note)})
		// H2b and H2c are read over the detected mutations, as their
		// definitions say ("every detected mutation"), so a miss counts in
		// H2a only; the rate over the detectable mutations is beside them.
		nt := PrimaryPooled(res.protocol, res.Runs, a, true)
		_, ntdet := primaryRates(res.protocol, res.Runs, a, true)
		for k, id := range []string{"H2b", "H2c"} {
			if t.Detected == 0 {
				v = append(v, Measurement{ID: id, Scope: scope, Measure: h2Measure(id), State: NotMeasured, Value: "no mutation was detected" + note})
				continue
			}
			d := fmt.Sprintf("over the detected mutations %s; over the detectable mutations %s", crText(rdet[k]), crText(rd[k+1]))
			if nt.Detected > 0 {
				d += fmt.Sprintf("; without the tool-heavy stratum, over the detected %s", crText(ntdet[k]))
			}
			v = append(v, Measurement{ID: id, Scope: scope, Measure: h2Measure(id), State: Measured, Value: d + note})
		}
	}
	// Retimed omissions (E-2): reported apart, outside H2a to H2c.
	if rt := RetimedPooled(res.Runs, ""); rt.AttackedRuns > 0 {
		v = append(v, Measurement{ID: "H2-retimed", Scope: "every agent, every capture", Measure: "retimed omissions, outside H2a to H2c: detection, and runs reporting later claims outside their interval",
			State: Measured, Value: fmt.Sprintf("%d of %d detectable detected, %d classified, %d located; %d of %d attacked runs report a claim outside its interval%s", rt.Detected, rt.Detectable, rt.Classified, rt.Located, rt.OutsideIntervalRuns, rt.AttackedRuns, note)})
	}
	// H2d: counterexamples to A4 suppressing nothing, alone and composed
	// with an omission. An omission with widened neighbours that is still
	// found (detected) but not classified or located is counted apart, as
	// H2b and H2c read those.
	viol, comp, partial, positions, lifetime := 0, 0, 0, 0, 0
	for _, a := range h.A4 {
		viol += len(a.Violations)
		lifetime += a.LifetimeDetected
		comp += len(a.ComposedNotFound)
		partial += len(a.ComposedMisses) - len(a.ComposedNotFound)
		positions += a.Positions + a.ComposedPositions
	}
	d := Measurement{ID: "H2d", Scope: "every agent, every capture", Measure: h2Measure("H2d")}
	if positions == 0 {
		d.State, d.Value = NotMeasured, "no position was checked"+note
	} else {
		d.State = Measured
		d.Value = fmt.Sprintf("%d positions checked: %d widening(s) changed the verdict and %d omission(s) with widened neighbours were not found; %d found but not classified or not located; %d widening(s) detected by a lifetime finding on the widened claim", positions, viol, comp, partial, lifetime)
	}
	v = append(v, d)
	// H2e: findings about a mutation marked undetectable by design. Any is a
	// contradiction of the E-5 criterion and a halt condition.
	e := Measurement{ID: "H2e", Scope: "every agent, every capture", Measure: h2Measure("H2e")}
	if h.Sessions == 0 {
		e.State, e.Value = NotMeasured, "no session was swept"
	} else {
		e.State, e.Value = Measured, fmt.Sprintf("%d finding(s) about a mutation the E-5 criterion marked undetectable by design", len(h.Contradictions))
	}
	if len(h.Contradictions) > 0 {
		halts = append(halts, fmt.Sprintf("H2e: %d finding(s) concern a mutation marked undetectable by design (see h2.contradictions in results.json): the E-5 criterion is contradicted", len(h.Contradictions)))
	}
	v = append(v, e)
	return v, halts
}

func runAgent(runs []RunOutput, id string) string {
	for _, o := range runs {
		if o.ID == id {
			return o.Agent
		}
	}
	return ""
}

func h2Measure(id string) string {
	switch id {
	case "H2a":
		return "detection of detectable, in-capture A1, A2 and A3 mutations"
	case "H2b":
		return "classification of detected mutations as their attack"
	case "H2c":
		return "localisation of detected mutations on the mutated entry"
	case "H2d":
		return "A4 counterexamples: widenings that change the verdict, alone and around an omission"
	case "H2e":
		return "findings about a mutation marked undetectable by design"
	}
	return ""
}
