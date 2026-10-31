package main

import (
	"fmt"
	"strings"
)

// MaxListed bounds how many individual cases the report prints per list; the
// results file holds all of them.
const MaxListed = 25

type md struct{ strings.Builder }

func (m *md) line(format string, args ...any) { fmt.Fprintf(&m.Builder, format+"\n", args...) }
func (m *md) blank()                          { m.WriteString("\n") }

// table writes a Markdown table.
func (m *md) table(header []string, rows [][]string) {
	m.line("| %s |", strings.Join(header, " | "))
	sep := make([]string, len(header))
	for i := range sep {
		sep[i] = "---"
	}
	m.line("| %s |", strings.Join(sep, " | "))
	for _, r := range rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = strings.ReplaceAll(c, "|", "/")
		}
		m.line("| %s |", strings.Join(cells, " | "))
	}
	m.blank()
}

func listed(m *md, label string, items []string) {
	if len(items) == 0 {
		return
	}
	m.line("%s (%d):", label, len(items))
	m.blank()
	for i, it := range items {
		if i == MaxListed {
			m.line("- ... and %d more in results.json", len(items)-MaxListed)
			break
		}
		m.line("- %s", it)
	}
	m.blank()
}

func num(p *float64, format string) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprintf(format, *p)
}

func cr(c ClusterRate) string {
	if c.Rate == nil {
		return "n/a"
	}
	s := fmt.Sprintf("%.3f", *c.Rate)
	if c.CI != nil {
		s += fmt.Sprintf(" %s", interval(c.CI))
	}
	if c.PerClusterMin != nil {
		s += fmt.Sprintf(" (session min %.3f)", *c.PerClusterMin)
	}
	return s
}

func rateCell(r Rate) string {
	if r.Rate == nil {
		return "n/a"
	}
	s := fmt.Sprintf("%d/%d = %.3f", r.Succeeded, r.Evaluated, *r.Rate)
	if r.Wilson != nil {
		s += " W" + interval(r.Wilson)
	}
	if r.Exact != nil {
		s += fmt.Sprintf(" CP-%s %.3f", r.Exact.Kind, r.Exact.Value)
	}
	return s
}

// Report renders report.md.
func Report(res *Results) string {
	m := &md{}
	m.line("# agent-trace analysis report")
	m.blank()
	m.line("Computed under %s.", res.Constants.Protocol)
	m.blank()
	m.line("- campaign `%s`, manifest sha256 `%s`, recorded at commit `%s`", res.Inputs.Campaign, res.Inputs.ManifestSHA256, res.Inputs.ManifestCommit)
	m.line("- agent version config `%s`, sha256 `%s`", res.Inputs.AgentConfig, res.Inputs.AgentConfigSHA256)
	m.line("- bootstrap: %d resamples, seed %d; Wilson 95%%; exact one-sided 95%% Clopper-Pearson at 0 or n", res.Constants.BootstrapResamples, res.Constants.BootstrapSeed)
	m.line("- primary baseline agreement %.2f of the controls; interval slack %d ms", res.Constants.PrimaryAgreement, res.Constants.IntervalSlackMS)
	m.line("- every rate carries three counts: considered (in scope), evaluated (the denominator), succeeded (the numerator, the runs or mutations with the property the rate names)")
	m.blank()

	m.line("## Halt conditions")
	m.blank()
	if len(res.Halts) == 0 {
		m.line("None of the halt conditions this command can read (protocol 10.2: an H2e contradiction, an unattributed INCONCLUSIVE) occurred. The others (instrument validation, redaction check, an unscripted probe event) are not computable from a campaign directory.")
	} else {
		m.line("**HALT. The campaign stops and the cause is investigated (protocol 10.2).**")
		m.blank()
		for _, h := range res.Halts {
			m.line("- **%s**", h)
		}
	}
	m.blank()
	if len(res.Warnings) > 0 {
		listed(m, "Warnings", res.Warnings)
	}

	m.line("## Verdicts")
	m.blank()
	m.line("One line per registered hypothesis against its registered threshold.")
	m.blank()
	rows := make([][]string, 0, len(res.Verdicts))
	for _, v := range res.Verdicts {
		rows = append(rows, []string{v.ID, v.Scope, v.Result, v.Claim, v.Threshold, v.Detail})
	}
	m.table([]string{"ID", "Scope", "Result", "Claim", "Registered threshold", "Evidence"}, rows)

	m.line("## Runs and exclusions")
	m.blank()
	var crow [][]string
	for _, c := range res.Counts {
		crow = append(crow, []string{c.Agent, c.Version, fmt.Sprint(c.Considered), fmt.Sprint(c.Completed), fmt.Sprint(c.Kept), fmt.Sprint(c.Swept),
			countsLine(c.ByRule), fmt.Sprintf("%d not completed, %d not stated", c.NotCompleted, c.CompletionUnknown), fmt.Sprintf("%d of %d differ", c.RunnerDisagrees, c.RunnerCompared)})
	}
	m.table([]string{"Agent", "Version", "Considered", "Completed (H3c, H3d)", "Kept (H3a, H3b, H2)", "Swept (H2)", "Excluded by rule", "Task completion (X5, reported)", "Outcome vs the runner's own verify"}, crow)
	var srow [][]string
	for _, s := range res.Slots {
		srow = append(srow, []string{s.Agent, fmt.Sprint(s.Slots), fmt.Sprint(s.FailedSlots), fmt.Sprint(s.MovedAside), num(s.FailedShare, "%.3f"), fmt.Sprint(s.OverLimit)})
	}
	m.line("Slots (X4): a slot that fails is reported as failed; more than %.0f%% failed slots per agent is itself a finding.", 100*MaxFailedSlotShare)
	m.blank()
	m.table([]string{"Agent", "Slots", "Failed slots", "Attempts moved aside", "Failed share", "Over the line"}, srow)
	var lines []string
	for _, l := range res.Excluded {
		var rs []string
		for _, e := range l.Exclusions {
			rs = append(rs, e.Rule+": "+e.Reason)
		}
		lines = append(lines, fmt.Sprintf("`%s` (%s %s %s), %s: %s", l.ID, l.Agent, l.Version, l.Task, l.Effect, strings.Join(rs, " | ")))
	}
	m.line("Every excluded run, with its reason and effect:")
	m.blank()
	if len(lines) == 0 {
		m.line("None.")
		m.blank()
	} else {
		for _, l := range lines {
			m.line("- %s", l)
		}
		m.blank()
	}

	reportTrace(m, res)
	reportH3(m, res)
	reportH2(m, res)
	reportH1(m, res)
	reportH4(m, res)

	m.line("## Not computed")
	m.blank()
	if len(res.NotComputed) == 0 {
		m.line("Nothing was skipped.")
	}
	for _, n := range res.NotComputed {
		m.line("- %s", n)
	}
	m.blank()
	return m.String()
}

func reportH3(m *md, res *Results) {
	m.line("## H3: false positives and INCONCLUSIVE on honest runs")
	m.blank()
	m.line("Task groups follow decision D8 (held-out: Claude Code `long`, agy `long` and `subagent`); `tool_heavy` is the named tool-heavy subgroup of decision D5. H3 is never pooled over versions.")
	m.blank()
	var rows [][]string
	for _, c := range res.H3.Cells {
		rows = append(rows, []string{c.Agent, c.Version, c.Scope, rateCell(c.RunFP), threeCounts(c.RunFP), rateCell(c.Faithful)})
	}
	m.table([]string{"Agent", "Version", "Scope", "H3a per-run FP (Findings() > 0 / kept runs)", "Counts", "H3d FAITHFUL (completed runs)"}, rows)

	rows = nil
	for _, c := range res.H3.Cells {
		f := c.ClaimFP
		rows = append(rows, []string{c.Agent, c.Version, c.Scope, fmt.Sprintf("%d/%d", f.Flagged, f.Claims), cr(f.Rate), fmt.Sprint(f.Sessions),
			fmt.Sprintf("%d (%d runs)", f.Unrecorded, f.RunsUnrecorded), fmt.Sprintf("%d (%d runs)", f.UnexplainedSubtrees, f.RunsSubtrees), fmt.Sprintf("%d (%d runs)", f.UnexplainedSensitive, f.RunsSensitive), fmt.Sprint(c.RunsWithHarnessSharedReads)})
	}
	m.line("H3b: per-claim FP rate (claims flagged Mismatched, Unwitnessed or OutsideInterval over the agent's own claims; cluster bootstrap over sessions), with the per-run counts that are not claims.")
	m.blank()
	m.table([]string{"Agent", "Version", "Scope", "Flagged/claims", "Rate and bootstrap 95%", "Sessions", "Unrecorded", "Unexplained subtrees", "Unexplained sensitive", "Runs with harness-shared reads"}, rows)

	rows = nil
	for _, c := range res.H3.Cells {
		i := c.Inconclusive
		rows = append(rows, []string{c.Agent, c.Version, c.Scope, rateCell(i.Rate), countsLine(i.Primary), countsLine(i.Multi), countsLine(i.Details)})
	}
	m.line("H3c: INCONCLUSIVE rate over completed runs, with causes under the protocol's fixed precedence (primary) and as multi-cause counts (a run counts under every cause it has).")
	m.blank()
	m.table([]string{"Agent", "Version", "Scope", "INCONCLUSIVE", "Primary cause", "Multi-cause", "Detail (loss counters, unverified fields)"}, rows)

	if len(res.H3.Sensitivity) > 0 {
		m.line("### H3 sensitivity: agreement 1/5 to 5/5 and the leave-one-out pooled baseline")
		m.blank()
		var srows [][]string
		for _, c := range res.H3.Sensitivity {
			srows = append(srows, []string{c.Agent, c.Version, c.Scope, c.Setting, rateCell(c.RunFP), cr(c.ClaimFP.Rate), rateCell(c.Inconclusive.Rate), rateCell(c.Faithful)})
		}
		m.table([]string{"Agent", "Version", "Scope", "Setting", "H3a", "H3b", "H3c INCONCLUSIVE", "H3d FAITHFUL"}, srows)
		var trows [][]string
		for _, t := range res.H3.TradeOffs {
			trows = append(trows, []string{t.Agent, t.Version, t.Setting, fmt.Sprint(t.Runs), num(t.MedianRestingReads, "%.1f"), num(t.MedianRestingWrites, "%.1f"), fmt.Sprintf("%d/%d", t.Undetectable, t.Claims), pct(t.UndetectableShare)})
		}
		m.line("What each setting buys and costs: the level-0 paths the baseline holds (V-36 reads, V-37 writes) and the undetectable-by-design single omissions that result (attack surface).")
		m.blank()
		m.table([]string{"Agent", "Version", "Setting", "Runs", "Median resting reads", "Median resting writes", "Undetectable single omissions / claims", "Share"}, trows)
	}
}

func reportH2(m *md, res *Results) {
	m.line("## H2: detection, classification and localisation")
	m.blank()
	h := res.H2
	if h == nil {
		m.line("Skipped (`--no-sweep`).")
		m.blank()
		return
	}
	if h.Reduced {
		m.line("**REDUCED SWEEP: seeds %d to %d, not the registered %d to %d. These are not the registered H2 numbers.**", SeedFirst, h.LastSeed, SeedFirst, SeedLast)
		m.blank()
	}
	m.line("%d sessions swept. Rates are over detectable in-capture mutations (E-5), with a bootstrap over sessions; undetectable by design, out of capture (an A2 or A3 claim set aside as out of scope, V-23) and unverifiable (A3 on a value the probe did not capture, V-22, V-26) are counted apart. Primary variants use uniform selection; `-sensitive` variants are secondary and outside the verdicts.", h.Sessions)
	m.blank()
	listed(m, "Runs set aside from the sweep (X5)", h.Excluded)
	var rows [][]string
	for _, c := range h.Cells {
		if c.Scope != H2ScopeAll || c.N != 0 {
			continue
		}
		t := c.Tally
		rows = append(rows, []string{c.Agent, c.Variant, fmt.Sprint(c.Sessions), fmt.Sprint(t.Mutations), fmt.Sprint(t.Distinct), fmt.Sprint(t.Detectable),
			fmt.Sprint(t.Undetectable), fmt.Sprint(t.OutOfCapture), fmt.Sprint(t.Unverifiable), cr(c.Detected), cr(c.Classified), cr(c.Located),
			fmt.Sprintf("%d/%d", t.AmbiguousRuns, t.AttackedRuns), fmt.Sprintf("%d (%d also on honest)", t.Unaccounted, t.UnaccountedHonest), fmt.Sprintf("%d/%d", t.NotFaithfulRuns, t.AttackedRuns), notGen(t)})
	}
	m.table([]string{"Agent", "Variant", "Sessions", "Mutations", "Distinct", "Detectable", "Undetectable by design", "Out of capture", "Unverifiable", "Detected", "Classified", "Located", "Ambiguous runs", "Unaccounted findings", "Runs NOT FAITHFUL", "Not generated"}, rows)

	m.line("Per agent, task and attack (all mutation counts pooled): detected, classified, located and the number of detectable mutations.")
	m.blank()
	rows = nil
	for _, c := range h.Cells {
		if c.N != 0 || !strings.HasPrefix(c.Scope, H2ScopeTask) || !c.Primary {
			continue
		}
		rows = append(rows, []string{c.Agent, c.Scope, c.Variant, fmt.Sprint(c.Tally.Detectable), fmt.Sprint(c.Tally.Distinct), cr(c.Detected), cr(c.Classified), cr(c.Located)})
	}
	m.table([]string{"Agent", "Scope", "Variant", "Detectable", "Distinct", "Detected", "Classified", "Located"}, rows)

	m.line("Sensitivity rows: each excluded category counted in turn as misses, beside the E-5 reading (primary variants, all counts pooled, detected / classified / located).")
	m.blank()
	rows = nil
	for _, c := range h.Cells {
		if c.Scope != H2ScopeAll || c.N != 0 || !c.Primary {
			continue
		}
		for _, s := range c.Sensitivity {
			rows = append(rows, []string{c.Agent, c.Variant, s.Name, fmt.Sprint(s.Den), num(s.DetectedRate, "%.3f"), num(s.ClassifiedRate, "%.3f"), num(s.LocatedRate, "%.3f")})
		}
	}
	m.table([]string{"Agent", "Variant", "Reading", "Denominator", "Detected", "Classified", "Located"}, rows)

	m.line("Run-level view of attacked runs (primary variants): what a user sees.")
	m.blank()
	rows = nil
	for _, c := range h.Cells {
		if c.Scope != H2ScopeAll || c.N != 0 || !c.Primary {
			continue
		}
		t := c.Tally
		rows = append(rows, []string{c.Agent, c.Variant, fmt.Sprint(t.AttackedRuns), fmt.Sprintf("%d (%s)", t.NotFaithfulRuns, pct(ratioPtr(t.NotFaithfulRuns, t.AttackedRuns))), fmt.Sprintf("%d (%s)", t.InconclusiveRuns, countsLine(t.InconclusiveCause)), fmt.Sprint(t.OutsideIntervalRuns), fmt.Sprint(t.RunsWithUnaccounted)})
	}
	m.table([]string{"Agent", "Variant", "Attacked runs", "NOT FAITHFUL", "INCONCLUSIVE (primary causes)", "Runs with claims outside their interval", "Runs with unaccounted findings"}, rows)

	m.line("### A4 and the composed check (H2d)")
	m.blank()
	rows = nil
	for _, a := range h.A4 {
		rows = append(rows, []string{a.Agent, fmt.Sprint(a.Sessions), fmt.Sprint(a.Positions), fmt.Sprint(len(a.Violations)), fmt.Sprint(a.ComposedPositions), fmt.Sprint(a.ComposedUndetectable), fmt.Sprintf("%d/%d/%d of %d", a.ComposedDetected, a.ComposedClassified, a.ComposedLocated, a.ComposedDetectable), fmt.Sprint(len(a.ComposedMisses))})
	}
	m.table([]string{"Agent", "Sessions", "Widened positions", "Violations", "Composed positions", "Composed undetectable by design", "Composed detected/classified/located of detectable", "Composed misses"}, rows)
	for _, a := range h.A4 {
		listed(m, a.Agent+": widening violations", a.Violations)
		listed(m, a.Agent+": composed misses", a.ComposedMisses)
	}

	m.line("### H2a: misses and H2e: contradictions")
	m.blank()
	if len(h.Contradictions) > 0 {
		m.line("**H2e CONTRADICTED: findings about omissions marked undetectable by design. This halts the campaign.**")
		m.blank()
		var cs []string
		for _, c := range h.Contradictions {
			cs = append(cs, fmt.Sprintf("`%s` %s n=%d seed %d: %s %s", c.Run, c.Variant, c.N, c.Seed, c.Kind, c.Entry))
		}
		listed(m, "Contradictions", cs)
	}
	var ms []string
	for _, x := range h.Misses {
		ms = append(ms, fmt.Sprintf("`%s` %s n=%d seed %d: %s of %s, Diagnose record in results.json (outcome %s, %d findings, %d unaccounted)", x.Run, x.Variant, x.N, x.Seed, x.Kind, x.Entry, x.Diagnosis.Outcome, len(x.Diagnosis.Findings), x.Diagnosis.Unaccounted))
	}
	if len(ms) == 0 {
		m.line("No detectable in-capture mutation was missed.")
		m.blank()
	}
	listed(m, "Detectable in-capture mutations not detected", ms)
	var oc []string
	for _, x := range h.OutOfCapture {
		oc = append(oc, fmt.Sprintf("`%s` %s n=%d seed %d: %s of %s", x.Run, x.Variant, x.N, x.Seed, x.Kind, x.Entry))
	}
	listed(m, "Mutations out of capture (counted apart, not misses)", oc)

	m.line("### Mislocation: where classification and localisation fail")
	m.blank()
	m.line("Each mutation not classified or not located, and each unaccounted finding not already on the honest run, is assigned from its Diagnose record to a category fixed in the protocol (5.7). A case the record does not decide mechanically is category 6 and listed. Mutations and findings are counted apart: one fabrication can appear as a mutation (category 1 or 2) and its interval finding as a finding (category 2).")
	m.blank()
	rows = nil
	for _, t := range h.Mislocation {
		if t.Total == 0 {
			continue
		}
		rows = append(rows, []string{t.Agent, t.Scope, fmt.Sprint(t.Total), countsLine(t.Mutation), countsLine(t.Finding)})
	}
	if len(rows) == 0 {
		m.line("No case.")
		m.blank()
	} else {
		m.table([]string{"Agent", "Scope", "Cases", "Mutations by category", "Findings by category"}, rows)
	}
	var others []string
	for _, c := range h.MislocationCases {
		if c.Category == Mis6 {
			others = append(others, fmt.Sprintf("`%s` %s n=%d seed %d, %s: %s", c.Run, c.Variant, c.N, c.Seed, c.Subject, c.What))
		}
	}
	listed(m, "Category 6, other, each case", others)

	m.line("### Attack surface per session")
	m.blank()
	m.line("A baseline-aware adaptive attacker against agent-trace would use these: the claims whose single omission is undetectable by design, from the honest run's verdict at the primary baseline.")
	m.blank()
	rows = nil
	for _, s := range h.Surface {
		rows = append(rows, []string{s.Agent, fmt.Sprint(s.Sessions), fmt.Sprint(s.Claims), fmt.Sprintf("%d (%s)", s.Undetectable, pct(s.Share)), pct(s.MinShare) + " to " + pct(s.MaxShare), fmt.Sprintf("%d, of which undetectable %d", s.SensitiveSelected, s.SensitiveUndetectable)})
	}
	m.table([]string{"Agent", "Sessions", "Claims", "Undetectable single omissions", "Per-session share, min to max", "Selected by attack.Sensitive"}, rows)

	m.line("### Premise check (protocol 5.2)")
	m.blank()
	m.line("The honest run verified through the attack path (normalized, without implied claims) and through the adapter path. Every difference is listed; a finding on the honest run through the attack path is a path artefact and is never attributed to a mutation.")
	m.blank()
	var pre []string
	artefacts := 0
	for _, p := range h.Premise {
		artefacts += p.HonestPathFindings
		for _, d := range p.Differences {
			pre = append(pre, fmt.Sprintf("`%s`: %s: attack path %s, adapter path %s", p.Run, d.What, d.AttackPath, d.AdapterPath))
		}
	}
	m.line("%d finding(s) on honest runs through the attack path (path artefacts); %d difference(s) between the two paths over %d sessions.", artefacts, len(pre), len(h.Premise))
	m.blank()
	listed(m, "Differences", pre)
	listed(m, "Generator errors", h.GeneratorErrors)
}

func notGen(t Tally) string {
	if len(t.NotGenerated) == 0 {
		return ""
	}
	return countsLine(t.NotGenerated)
}

func reportH1(m *md, res *Results) {
	m.line("## H1: existing tools accept the attacks")
	m.blank()
	h := res.H1
	if h == nil {
		m.line("Not computed (see Not computed).")
		m.blank()
		return
	}
	m.line("Read from the comparison sweep `%s` (agent-trace commit `%s`%s); the harnesses are not reimplemented. Acceptance is accepted over evaluated trajectories with a bootstrap over sessions (fixtures). Cells whose controls did not hold are UNJUDGED and not counted. %d harness error(s).", h.Dir, h.Commit, map[bool]string{true: ", dirty tree", false: ""}[h.Dirty], h.HarnessErrors)
	m.blank()
	var rows [][]string
	for _, r := range h.Rows {
		st := r.Status
		rows = append(rows, []string{r.Tool, r.Condition, r.Attacker, r.Kind, fmt.Sprintf("%d/%d", r.Accepted, r.Evaluated), cr(r.Acceptance), fmt.Sprint(r.Sessions), fmt.Sprint(r.Distinct),
			fmt.Sprintf("considered %d, not representable %d, refused %d, inapplicable %d, errors %d, unjudged %d", r.Considered, r.NotRepresentable, r.Refused, r.Inapplicable, r.Errors, r.Unjudged), st})
	}
	m.table([]string{"Tool", "Row", "Attacker", "Kind", "Accepted/evaluated", "Acceptance and bootstrap 95%", "Sessions", "Distinct mutations", "Counts", "Status"}, rows)
	m.line("Control rows (they do not test H1; if one fails the matching H1 row is UNJUDGED):")
	m.blank()
	rows = nil
	for _, c := range h.Controls {
		rows = append(rows, []string{c.Tool, c.Condition, c.Kind, fmt.Sprintf("%d/%d detected", c.Detected, c.Evaluated), fmt.Sprint(c.Held)})
	}
	m.table([]string{"Tool", "Row", "Kind", "Detected", "Behaved as registered"}, rows)
	var cr2 [][]string
	for _, k := range sortedKeys(h.ControlRowCounts) {
		cr2 = append(cr2, []string{k, countsLine(h.ControlRowCounts[k])})
	}
	m.line("The sweep's own control rows (honest trajectory, drop without re-sealing, checkpoint after the attack):")
	m.blank()
	m.table([]string{"Control", "Outcomes"}, cr2)
	if e := h.EditSplit; e != nil {
		m.line("Also reported, not tested: the edit criterion detected %d of %d Write and Edit mutations (%s) and %d of %d others. Split by whether the mutation changes the replayed final state: %s.", e.EditDetected, e.EditMutations, pct(e.EditDetectionRate), e.NonEditDetected, e.NonEditMutations, e.NotSplitByFinalState)
		m.blank()
	}
	if n := h.NaiveCommandA3; n != nil {
		m.line("Footnote row: the command criterion against a naive attacker on A3 accepted %d of %d.", n.Accepted, n.Evaluated)
		m.blank()
	}
	m.line("agent-trace's own row on the same trajectories is the H2 table above.")
	m.blank()
}

func reportH4(m *md, res *Results) {
	m.line("## H4: overhead")
	m.blank()
	for _, b := range res.H4.Bench {
		m.line("### H4a, run `%s`", b.Label)
		m.blank()
		var rows [][]string
		for _, r := range b.Rows {
			rows = append(rows, []string{r.Name, r.Condition, fmt.Sprintf("%d ok of %d", r.OK, r.Runs), sumCell(r.WallRatio, "%.3f"), ciCell(r.WallRatioCI), sumCell(r.CPURatio, "%.3f"), sumCell(r.FixedCostS, "%.3f"), sumCell(r.WatchCPUS, "%.3f"), sumCell(r.PeakRSSMiB, "%.1f"), fmt.Sprint(r.WithLoss)})
		}
		m.table([]string{"Workload", "Condition", "Runs", "Wall ratio median [q1, q3] top1", "Median bootstrap 95%", "CPU ratio", "Fixed cost s", "Watch CPU s", "Peak RSS MiB", "Runs with loss"}, rows)
		var lrows [][]string
		for _, l := range b.Limits {
			lrows = append(lrows, []string{l.ID, l.Result, l.Limit, l.Detail})
		}
		m.table([]string{"ID", "Result", "D3 limit", "Detail"}, lrows)
		if len(b.Drift) > 0 {
			var drows [][]string
			for _, d := range b.Drift {
				drows = append(drows, []string{d.Name, d.Condition, fmt.Sprintf("%.3f", d.Before), fmt.Sprintf("%.3f", d.After), fmt.Sprintf("%+.3f", d.Change)})
			}
			m.line("Machine drift between this run and the run repeated after the campaign (median wall ratio):")
			m.blank()
			m.table([]string{"Workload", "Condition", "Before", "After", "Change"}, drows)
		}
	}
	m.line("### H4b: real sessions (per session and per claim; median [q1, q3] top1)")
	m.blank()
	var rows [][]string
	for _, c := range res.H4.Real {
		rows = append(rows, []string{c.Agent, c.Version, fmt.Sprint(c.Sessions), sumCell(c.DurationS, "%.0f"), sumCell(c.Claims, "%.0f"), sumCell(c.Events, "%.0f"), sumCell(c.CaptureBytes, "%.0f"), sumCell(c.BytesPerEvent, "%.0f"), sumCell(c.CapabilityEvents, "%.0f"), sumCell(c.CapabilityBytes, "%.0f"),
			sumCell(c.EventsPerClaim, "%.1f"), sumCell(c.CaptureBytesPerClaim, "%.0f"), sumCell(c.DurationPerClaimS, "%.2f")})
	}
	m.table([]string{"Agent", "Version", "Sessions", "Duration s", "Claims", "Events", "Capture bytes", "Bytes per event", "Capability events", "Capability bytes", "Events per claim", "Capture bytes per claim", "Seconds per claim"}, rows)
	var nm []string
	for _, c := range res.H4.Real {
		if len(c.NotMeasured) > 0 {
			nm = append(nm, fmt.Sprintf("%s %s: sessions without the field: %s", c.Agent, c.Version, countsLine(c.NotMeasured)))
		}
	}
	listed(m, "Not measured (the manifest and logs do not carry the field)", nm)
}

func sumCell(s *Summary, format string) string {
	if s == nil {
		return "n/a"
	}
	f := func(x float64) string { return fmt.Sprintf(format, x) }
	return fmt.Sprintf("%s [%s, %s] %s", f(s.Median), f(s.Q1), f(s.Q3), f(s.Top1))
}

func ciCell(i *Interval) string {
	if i == nil {
		return "n/a"
	}
	return interval(i)
}

// reportTrace lists the runs whose trace was tampered with or could not be
// read (V-59): results, not exclusions.
func reportTrace(m *md, res *Results) {
	m.line("## Trace tampering and unreadable traces (V-59)")
	m.blank()
	m.line("A run whose trace a process other than the harness's changed, or that claims a write to it, has a trace-tampering finding (NOT FAITHFUL; in an honest campaign it counts in H3a). A run whose trace was missing, empty or damaged at verification cannot be verified (INCONCLUSIVE, the cause %s in H3c, or NOT FAITHFUL with tampering) and is set aside from the attack sweep. Neither is an exclusion.", CauseTrace)
	m.blank()
	if len(res.Trace) == 0 {
		m.line("None.")
		m.blank()
		return
	}
	rows := make([][]string, 0, len(res.Trace))
	for _, t := range res.Trace {
		state := t.State
		if state == "" {
			state = "read"
		}
		rows = append(rows, []string{"`" + t.ID + "`", t.Agent, t.Version, t.Task, state, fmt.Sprint(t.Tampering), t.Outcome, t.Annotated})
	}
	m.table([]string{"Run", "Agent", "Version", "Task", "Trace", "Tampering evidence", "Outcome", "Runner's record"}, rows)
}
