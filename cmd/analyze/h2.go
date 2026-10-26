package main

import "strings"

// H2: detection, classification and localisation of A1 to A3, and A4
// suppressing nothing (protocol sections 4 and 5).

// H2 scopes: an agent pooled over versions, one of its tasks, or one version
// (the only stratification H2 pools over, protocol 6.1).
const (
	H2ScopeAll     = "all"
	H2ScopeTask    = "task:"
	H2ScopeVersion = "version:"
)

// SensRow is one row of the sensitivity table: the strict reading beside
// the E-5 reading, counting a category as misses.
type SensRow struct {
	Name           string   `json:"name"`
	Den            int      `json:"den"`
	DetectedRate   *float64 `json:"detected_rate"`
	ClassifiedRate *float64 `json:"classified_rate"`
	LocatedRate    *float64 `json:"located_rate"`
}

// H2Cell is the numbers of one (agent, scope, variant, mutation count).
type H2Cell struct {
	Agent   string `json:"agent"`
	Scope   string `json:"scope"`
	Variant string `json:"variant"`
	// N is the mutation count, 0 for all counts pooled.
	N       int  `json:"n"`
	Primary bool `json:"primary"`
	// Sessions is how many sessions contributed a verified mutation.
	Sessions int   `json:"sessions"`
	Tally    Tally `json:"tally"`
	// Detected, Classified and Located are rates over the detectable
	// mutations with a session-cluster bootstrap; the distinct count is
	// Tally.Distinct.
	Detected   ClusterRate `json:"detected"`
	Classified ClusterRate `json:"classified"`
	Located    ClusterRate `json:"located"`
	// ClassifiedOfDetected is classified over detected, the reading of H2b
	// that does not charge misses to classification.
	ClassifiedOfDetected *float64  `json:"classified_of_detected"`
	Sensitivity          []SensRow `json:"sensitivity"`
}

// MislocationTable counts the mislocation assignments of an agent and scope.
type MislocationTable struct {
	Agent    string         `json:"agent"`
	Scope    string         `json:"scope"`
	Mutation map[string]int `json:"mutations_by_category"`
	Finding  map[string]int `json:"findings_by_category"`
	Total    int            `json:"total"`
}

// SurfaceSummary aggregates the attack surface (protocol 5.6) of an agent.
type SurfaceSummary struct {
	Agent                 string   `json:"agent"`
	Sessions              int      `json:"sessions"`
	Claims                int      `json:"claims"`
	Undetectable          int      `json:"undetectable_single_omissions"`
	Share                 *float64 `json:"undetectable_share"`
	MinShare              *float64 `json:"per_session_min_share"`
	MaxShare              *float64 `json:"per_session_max_share"`
	SensitiveSelected     int      `json:"sensitive_selected"`
	SensitiveUndetectable int      `json:"sensitive_selected_undetectable"`
}

// A4Summary pools the H2d checks.
type A4Summary struct {
	Agent                string   `json:"agent"`
	Sessions             int      `json:"sessions"`
	Positions            int      `json:"positions"`
	Violations           []string `json:"violations,omitempty"`
	ComposedPositions    int      `json:"composed_positions"`
	ComposedUndetectable int      `json:"composed_undetectable_by_design"`
	ComposedDetectable   int      `json:"composed_detectable"`
	ComposedDetected     int      `json:"composed_detected"`
	ComposedClassified   int      `json:"composed_classified"`
	ComposedLocated      int      `json:"composed_located"`
	ComposedNotFound     []string `json:"composed_not_found,omitempty"`
	ComposedMisses       []string `json:"composed_misses,omitempty"`
}

// Premise lists, per run, the differences of the premise check (5.2).
type Premise struct {
	Run                string       `json:"run"`
	Differences        []Difference `json:"differences,omitempty"`
	HonestPathFindings int          `json:"honest_attack_path_findings"`
}

// H2Results is the whole H2 section.
type H2Results struct {
	// LastSeed is the highest seed run; Reduced is true when it is below the
	// registered SeedLast, which makes the sweep not the registered one.
	LastSeed uint64 `json:"last_seed"`
	Reduced  bool   `json:"reduced"`
	// Sessions is how many runs the sweep covered; Excluded lists the runs
	// X5 set aside (fewer than two claims).
	Sessions         int                `json:"sessions"`
	Excluded         []string           `json:"excluded_runs,omitempty"`
	Cells            []H2Cell           `json:"cells"`
	Misses           []Miss             `json:"misses,omitempty"`
	OutOfCapture     []SetAside         `json:"out_of_capture,omitempty"`
	Contradictions   []Contradiction    `json:"contradictions,omitempty"`
	A4               []A4Summary        `json:"a4"`
	Mislocation      []MislocationTable `json:"mislocation"`
	MislocationCases []MislocationCase  `json:"mislocation_cases,omitempty"`
	Surface          []SurfaceSummary   `json:"attack_surface"`
	Premise          []Premise          `json:"premise_check"`
	GeneratorErrors  []string           `json:"generator_errors,omitempty"`
}

func h2Scopes(runs []RunOutput, agentName string) []string {
	tasks, versions := map[string]bool{}, map[string]bool{}
	for _, o := range runs {
		if o.Agent == agentName && o.Attack != nil {
			tasks[o.Task] = true
			versions[o.Version] = true
		}
	}
	out := []string{H2ScopeAll}
	for _, t := range sortedKeys(tasks) {
		out = append(out, H2ScopeTask+t)
	}
	if len(versions) > 1 {
		for _, v := range sortedKeys(versions) {
			out = append(out, H2ScopeVersion+v)
		}
	}
	return out
}

func h2InScope(o RunOutput, scope string) bool {
	switch {
	case scope == H2ScopeAll:
		return true
	case strings.HasPrefix(scope, H2ScopeTask):
		return o.Task == strings.TrimPrefix(scope, H2ScopeTask)
	case strings.HasPrefix(scope, H2ScopeVersion):
		return o.Version == strings.TrimPrefix(scope, H2ScopeVersion)
	}
	return false
}

// buildH2Cell pools the tallies of a variant (and mutation count, 0 for all)
// over the sessions of a scope.
func buildH2Cell(runs []RunOutput, agentName, scope string, spec GenSpec, n int) H2Cell {
	c := H2Cell{Agent: agentName, Scope: scope, Variant: spec.Variant, N: n, Primary: spec.Primary()}
	c.Tally = Tally{Variant: spec.Variant, N: n}
	var clusters []Cluster
	for _, o := range runs {
		if o.Agent != agentName || o.Attack == nil || !h2InScope(o, scope) {
			continue
		}
		var det, cls, loc, den float64
		contributed := false
		for _, t := range o.Attack.Tallies {
			if t.Variant != spec.Variant || (n != 0 && t.N != n) {
				continue
			}
			tt := *t
			c.Tally.merge(&tt)
			if t.AttackedRuns > 0 {
				contributed = true
			}
			den += float64(t.Detectable)
			det += float64(t.Detected)
			cls += float64(t.Classified)
			loc += float64(t.Located)
		}
		if n == 0 {
			// Distinct over all the variant's counts, not their sum.
			c.Tally.Distinct -= sumDistinct(o.Attack, spec.Variant)
			c.Tally.Distinct += o.Attack.VariantDistinct[spec.Variant]
		}
		if contributed {
			c.Sessions++
		}
		clusters = append(clusters, Cluster{Den: den, Nums: []float64{det, cls, loc}})
	}
	b := ClusterBootstrap(clusters, 3, BootstrapResamples, BootstrapSeed)
	c.Detected, c.Classified, c.Located = b[0], b[1], b[2]
	c.ClassifiedOfDetected = ratioPtr(c.Tally.Classified, c.Tally.Detected)
	t := c.Tally
	row := func(name string, den int) SensRow {
		return SensRow{Name: name, Den: den, DetectedRate: ratioPtr(t.Detected, den), ClassifiedRate: ratioPtr(t.Classified, den), LocatedRate: ratioPtr(t.Located, den)}
	}
	c.Sensitivity = []SensRow{
		row("E-5 reading (detectable in capture only)", t.Detectable),
		row("undetectable by design counted as misses", t.Detectable+t.Undetectable),
		row("out of capture counted as misses", t.Detectable+t.OutOfCapture),
		row("unverifiable counted as misses", t.Detectable+t.Unverifiable),
		row("strict reading (all three counted as misses)", t.Detectable+t.Undetectable+t.OutOfCapture+t.Unverifiable),
	}
	return c
}

func sumDistinct(a *AttackRun, variant string) int {
	n := 0
	for _, t := range a.Tallies {
		if t.Variant == variant {
			n += t.Distinct
		}
	}
	return n
}

// BuildH2 computes the H2 section from the processed runs.
func BuildH2(runs []RunOutput, lastSeed uint64) *H2Results {
	r := &H2Results{LastSeed: lastSeed, Reduced: lastSeed < SeedLast}
	agents := map[string]bool{}
	for _, o := range runs {
		if o.SweepExclusion != nil {
			r.Excluded = append(r.Excluded, o.ID+": "+o.SweepExclusion.Reason)
		}
		if o.Attack == nil {
			continue
		}
		r.Sessions++
		agents[o.Agent] = true
		r.Misses = append(r.Misses, o.Attack.Misses...)
		r.OutOfCapture = append(r.OutOfCapture, o.Attack.OutOfCapture...)
		r.Contradictions = append(r.Contradictions, o.Attack.Contradictions...)
		r.MislocationCases = append(r.MislocationCases, o.Attack.Mislocation...)
		r.GeneratorErrors = append(r.GeneratorErrors, o.Attack.GeneratorErrors...)
		r.Premise = append(r.Premise, Premise{Run: o.ID, Differences: o.Attack.Premise, HonestPathFindings: o.Attack.PathArtifacts})
	}
	specs := GenSpecs()
	variants := []GenSpec{}
	seen := map[string]bool{}
	for _, sp := range specs {
		if !seen[sp.Variant] {
			seen[sp.Variant] = true
			variants = append(variants, sp)
		}
	}
	for _, a := range sortedKeys(agents) {
		for _, scope := range h2Scopes(runs, a) {
			for _, v := range variants {
				for n := 0; n <= 3; n++ {
					if n != 0 {
						ok := false
						for _, sp := range specs {
							if sp.Variant == v.Variant && sp.N == n {
								ok = true
							}
						}
						if !ok {
							continue
						}
					}
					cell := buildH2Cell(runs, a, scope, specFor(specs, v.Variant, n), n)
					if cell.Tally.AttackedRuns == 0 && len(cell.Tally.NotGenerated) == 0 {
						continue
					}
					r.Cells = append(r.Cells, cell)
				}
			}
		}
		r.A4 = append(r.A4, buildA4(runs, a))
		r.Surface = append(r.Surface, buildSurface(runs, a))
		r.Mislocation = append(r.Mislocation, buildMislocation(runs, a, H2ScopeAll, func(RunOutput) bool { return true }))
		tasks := map[string]bool{}
		for _, o := range runs {
			if o.Agent == a && o.Attack != nil {
				tasks[o.Task] = true
			}
		}
		for _, t := range sortedKeys(tasks) {
			t := t
			r.Mislocation = append(r.Mislocation, buildMislocation(runs, a, H2ScopeTask+t, func(o RunOutput) bool { return o.Task == t }))
		}
		r.Mislocation = append(r.Mislocation, buildMislocation(runs, a, ScopeToolHeavy, func(o RunOutput) bool { return IsToolHeavy(a, o.Task) }))
	}
	return r
}

func specFor(specs []GenSpec, variant string, n int) GenSpec {
	for _, sp := range specs {
		if sp.Variant == variant && (n == 0 || sp.N == n) {
			return sp
		}
	}
	return GenSpec{Variant: variant}
}

func buildA4(runs []RunOutput, agentName string) A4Summary {
	s := A4Summary{Agent: agentName}
	for _, o := range runs {
		if o.Agent != agentName || o.Attack == nil {
			continue
		}
		a := o.Attack.A4
		s.Sessions++
		s.Positions += a.Positions
		for _, v := range a.Violations {
			s.Violations = append(s.Violations, o.ID+": "+v)
		}
		s.ComposedPositions += a.ComposedPositions
		s.ComposedUndetectable += a.ComposedUndetectable
		s.ComposedDetectable += a.ComposedDetectable
		s.ComposedDetected += a.ComposedDetected
		s.ComposedClassified += a.ComposedClassified
		s.ComposedLocated += a.ComposedLocated
		for _, m := range a.ComposedNotFound {
			s.ComposedNotFound = append(s.ComposedNotFound, o.ID+": "+m)
		}
		for _, m := range a.ComposedMisses {
			s.ComposedMisses = append(s.ComposedMisses, o.ID+": "+m)
		}
	}
	return s
}

func buildSurface(runs []RunOutput, agentName string) SurfaceSummary {
	s := SurfaceSummary{Agent: agentName}
	for _, o := range runs {
		sf, ok := o.Surfaces[SettingPrimary]
		if o.Agent != agentName || o.Attack == nil || !ok {
			continue
		}
		s.Sessions++
		s.Claims += sf.Claims
		s.Undetectable += sf.Undetectable
		s.SensitiveSelected += sf.SensitiveSelected
		s.SensitiveUndetectable += sf.SensitiveUndetectable
		if sf.UndetectableFraction != nil {
			if s.MinShare == nil || *sf.UndetectableFraction < *s.MinShare {
				s.MinShare = fptr(*sf.UndetectableFraction)
			}
			if s.MaxShare == nil || *sf.UndetectableFraction > *s.MaxShare {
				s.MaxShare = fptr(*sf.UndetectableFraction)
			}
		}
	}
	s.Share = ratioPtr(s.Undetectable, s.Claims)
	return s
}

func buildMislocation(runs []RunOutput, agentName, scope string, in func(RunOutput) bool) MislocationTable {
	t := MislocationTable{Agent: agentName, Scope: scope, Mutation: map[string]int{}, Finding: map[string]int{}}
	for _, o := range runs {
		if o.Agent != agentName || o.Attack == nil || !in(o) {
			continue
		}
		for _, c := range o.Attack.Mislocation {
			key := mislocationName(c.Category)
			if c.Subject == "mutation" {
				t.Mutation[key]++
			} else {
				t.Finding[key]++
			}
			t.Total++
		}
	}
	return t
}

// mislocationName names a mislocation category.
func mislocationName(cat int) string {
	switch cat {
	case Mis1:
		return "1 fabrication paired as a mismatch inside its interval"
	case Mis2:
		return "2 fabrication paired as a mismatch outside its interval"
	case Mis3:
		return "3 truthful claim that lost its event to a mutated neighbour"
	case Mis4:
		return "4 substitution of a harness-shared read's target"
	case Mis5:
		return "5 substitution paired with another observed event of its type"
	}
	return "6 other"
}

// PrimaryPooled sums the tallies of the variants that count toward the
// verdicts (InVerdict) of an agent over all its sessions: rates over every such
// mutation, and the same without the tool-heavy stratum.
func PrimaryPooled(runs []RunOutput, agentName string, excludeToolHeavy bool) Tally {
	var t Tally
	for _, o := range runs {
		if (agentName != "" && o.Agent != agentName) || o.Attack == nil {
			continue
		}
		if excludeToolHeavy && IsToolHeavy(o.Agent, o.Task) {
			continue
		}
		for _, tl := range o.Attack.Tallies {
			sp := specOf(tl.Variant)
			if !sp.InVerdict() {
				continue
			}
			tt := *tl
			t.merge(&tt)
		}
	}
	return t
}

// RetimedPooled sums the retimed omissions of an agent, reported apart.
func RetimedPooled(runs []RunOutput, agentName string) Tally {
	var t Tally
	for _, o := range runs {
		if (agentName != "" && o.Agent != agentName) || o.Attack == nil {
			continue
		}
		for _, tl := range o.Attack.Tallies {
			if sp := specOf(tl.Variant); sp.Primary() && sp.Retime {
				tt := *tl
				t.merge(&tt)
			}
		}
	}
	return t
}

func specOf(variant string) GenSpec {
	for _, sp := range GenSpecs() {
		if sp.Variant == variant {
			return sp
		}
	}
	return GenSpec{}
}
