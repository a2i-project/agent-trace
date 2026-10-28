package main

import (
	"errors"
	"fmt"
	"sort"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/attack"
	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The attack sweep of protocol section 5, run in process over one session: the
// generators of 5.3, the baseline of the run's own controls at the primary
// agreement, the premise check of 5.2, the A4 checks of H2d, and the mislocation
// categories of 5.7.

// Mutation classes of the sweep. Only "detectable" mutations enter the
// registered rates (E-5); the other three are counted apart.
const (
	ClassDetectable   = "detectable"
	ClassUndetectable = "undetectable_by_design"
	ClassOutOfCapture = "out_of_capture"
	ClassUnverifiable = "unverifiable"
)

// mislocation categories, protocol 5.7.
const (
	Mis1 = 1 // fabrication paired as a mismatch inside its interval
	Mis2 = 2 // the same, outside its interval
	Mis3 = 3 // truthful claim that lost its event to a mutated neighbour
	Mis4 = 4 // substitution of a harness-shared read's target
	Mis5 = 5 // substitution paired with another observed event of its type
	Mis6 = 6 // other, each case listed
)

// Tally counts one (variant, n) cell of one session, and sums over sessions.
type Tally struct {
	Variant string `json:"variant"`
	N       int    `json:"n"`
	// AttackedRuns counts verified mutated trajectories; NotGenerated the
	// requests the trajectory did not admit, by reason.
	AttackedRuns int            `json:"attacked_runs"`
	NotGenerated map[string]int `json:"not_generated,omitempty"`
	Mutations    int            `json:"mutations"`
	Distinct     int            `json:"distinct_mutations"`
	Detectable   int            `json:"detectable"`
	Undetectable int            `json:"undetectable_by_design"`
	OutOfCapture int            `json:"out_of_capture"`
	Unverifiable int            `json:"unverifiable"`
	Detected     int            `json:"detected"`
	Classified   int            `json:"classified"`
	Located      int            `json:"located"`
	// UndetectableDetected counts omissions marked undetectable by design that
	// a finding was about anyway: H2e's contradiction.
	UndetectableDetected int `json:"undetectable_detected"`
	// The run-level view: what a user sees of an attacked run.
	NotFaithfulRuns   int            `json:"not_faithful_runs"`
	InconclusiveRuns  int            `json:"inconclusive_runs"`
	InconclusiveCause map[string]int `json:"inconclusive_primary_causes,omitempty"`
	AmbiguousRuns     int            `json:"ambiguous_runs"`
	// Unaccounted counts findings no mutation explains; of them
	// UnaccountedHonest were already on the honest run through the attack
	// path (path artefacts, protocol 5.2, never attributed to a mutation).
	Unaccounted         int `json:"unaccounted_findings"`
	UnaccountedHonest   int `json:"unaccounted_also_on_honest_run"`
	RunsWithUnaccounted int `json:"runs_with_unaccounted"`
	// OutsideIntervalRuns counts runs reporting claims outside their interval
	// (the retimed omissions' side effect, E-2).
	OutsideIntervalRuns int `json:"runs_with_outside_interval"`

	seen  map[string]bool
	vseen map[string]bool
}

func (t *Tally) addNotGenerated(reason string) {
	if t.NotGenerated == nil {
		t.NotGenerated = map[string]int{}
	}
	t.NotGenerated[reason]++
}

// merge adds another tally of the same cell; distinct counts add, since each
// session's mutations are its own cases.
func (t *Tally) merge(o *Tally) {
	t.AttackedRuns += o.AttackedRuns
	for k, v := range o.NotGenerated {
		if t.NotGenerated == nil {
			t.NotGenerated = map[string]int{}
		}
		t.NotGenerated[k] += v
	}
	t.Mutations += o.Mutations
	t.Distinct += o.Distinct
	t.Detectable += o.Detectable
	t.Undetectable += o.Undetectable
	t.OutOfCapture += o.OutOfCapture
	t.Unverifiable += o.Unverifiable
	t.Detected += o.Detected
	t.Classified += o.Classified
	t.Located += o.Located
	t.UndetectableDetected += o.UndetectableDetected
	t.NotFaithfulRuns += o.NotFaithfulRuns
	t.InconclusiveRuns += o.InconclusiveRuns
	for k, v := range o.InconclusiveCause {
		if t.InconclusiveCause == nil {
			t.InconclusiveCause = map[string]int{}
		}
		t.InconclusiveCause[k] += v
	}
	t.AmbiguousRuns += o.AmbiguousRuns
	t.Unaccounted += o.Unaccounted
	t.UnaccountedHonest += o.UnaccountedHonest
	t.RunsWithUnaccounted += o.RunsWithUnaccounted
	t.OutsideIntervalRuns += o.OutsideIntervalRuns
}

// Miss is a detectable, in-capture mutation no finding was about (H2a), with
// its Diagnose record.
type Miss struct {
	Run       string           `json:"run"`
	Variant   string           `json:"variant"`
	N         int              `json:"n"`
	Seed      uint64           `json:"seed"`
	Kind      attack.Kind      `json:"kind"`
	Index     int              `json:"original_index"`
	Field     string           `json:"field,omitempty"`
	Entry     string           `json:"entry"`
	Diagnosis attack.Diagnosis `json:"diagnosis"`
}

// SetAside is a mutation counted apart from the detectable ones because it
// names an action the capture could not observe (out of capture), listed so
// a reader sees each case.
type SetAside struct {
	Run     string      `json:"run"`
	Variant string      `json:"variant"`
	N       int         `json:"n"`
	Seed    uint64      `json:"seed"`
	Kind    attack.Kind `json:"kind"`
	Index   int         `json:"original_index"`
	Entry   string      `json:"entry"`
}

// Contradiction is an omission marked undetectable by design that a finding
// was about: the E-5 criterion's contradiction, H2e, a halt condition.
type Contradiction struct {
	Run     string      `json:"run"`
	Variant string      `json:"variant"`
	N       int         `json:"n"`
	Seed    uint64      `json:"seed"`
	Kind    attack.Kind `json:"kind"`
	Entry   string      `json:"entry"`
}

// MislocationCase is one mutation or finding assigned to a mislocation category.
type MislocationCase struct {
	Run      string `json:"run"`
	Variant  string `json:"variant"`
	N        int    `json:"n"`
	Seed     uint64 `json:"seed"`
	Subject  string `json:"subject"` // "mutation" or "finding"
	Category int    `json:"category"`
	What     string `json:"what"`
}

// A4Result is the H2d check on one session.
type A4Result struct {
	// Positions is how many single widenings were checked (every claim the
	// widening changes); Violations lists those that changed the verdict.
	Positions  int      `json:"positions"`
	Violations []string `json:"violations,omitempty"`
	// The composed check: an omission with both neighbours widened over it,
	// at every position with a neighbour on each side.
	ComposedPositions    int `json:"composed_positions"`
	ComposedUndetectable int `json:"composed_undetectable_by_design"`
	ComposedDetectable   int `json:"composed_detectable"`
	ComposedDetected     int `json:"composed_detected"`
	ComposedClassified   int `json:"composed_classified"`
	ComposedLocated      int `json:"composed_located"`
	// ComposedNotFound lists positions where a detectable omission was not
	// detected: H2d's counterexamples ("still found"). ComposedMisses lists
	// those not detected, classified and located, reported beside them.
	ComposedNotFound []string `json:"composed_not_found,omitempty"`
	ComposedMisses   []string `json:"composed_misses,omitempty"`
}

// DiagRun is one entry of the optional diagnostics file.
type DiagRun struct {
	Run       string           `json:"run"`
	Variant   string           `json:"variant"`
	N         int              `json:"n"`
	Diagnosis attack.Diagnosis `json:"diagnosis"`
}

// AttackRun is everything the sweep found on one session.
type AttackRun struct {
	Claims          int               `json:"claims"`
	Tallies         []*Tally          `json:"tallies"`
	Misses          []Miss            `json:"misses,omitempty"`
	OutOfCapture    []SetAside        `json:"out_of_capture,omitempty"`
	Contradictions  []Contradiction   `json:"contradictions,omitempty"`
	Mislocation     []MislocationCase `json:"mislocation,omitempty"`
	A4              A4Result          `json:"a4"`
	Premise         []Difference      `json:"premise_differences,omitempty"`
	PathArtifacts   int               `json:"honest_attack_path_findings"`
	GeneratorErrors []string          `json:"generator_errors,omitempty"`
	// VariantDistinct counts the distinct mutations of each variant over all
	// its mutation counts (a single omission recurs inside the pairs).
	VariantDistinct map[string]int `json:"variant_distinct_mutations"`
	Diag            []DiagRun      `json:"-"`
}

// SweepOptions bounds the sweep.
type SweepOptions struct {
	// LastSeed is the highest seed run (the registered value is SeedLast).
	LastSeed uint64
	// Diagnostics keeps the Diagnose record of every run NeedsDiagnosis
	// selects, for the optional diagnostics file.
	Diagnostics bool
}

func generate(spec GenSpec, claims models.Trajectory, seed uint64, pos int, avoid map[string]bool) (models.Trajectory, attack.Record, error) {
	opt := attack.Options{N: spec.N, Seed: seed, Avoid: avoid, Retime: spec.Retime}
	if spec.Select == SelSensitive {
		opt.Select = attack.Sensitive
	}
	switch spec.Kind {
	case attack.Omission:
		if spec.Exhaustive {
			opt.Indices = []int{pos}
		}
		return attack.Omit(claims, opt)
	case attack.Fabrication:
		return attack.Fabricate(claims, opt)
	case attack.Substitution:
		return attack.Substitute(claims, attack.SubstituteOptions{Options: opt, Field: spec.Field})
	}
	return nil, attack.Record{}, fmt.Errorf("no generator for %s", spec.Kind)
}

// Sweep runs every registered mutation over one session. b is the baseline
// from the run's own controls at the primary agreement.
func (s *Session) Sweep(b *agent.Baseline, opts SweepOptions) *AttackRun {
	// The generators mutate the agent's own claims; the attacked run is
	// verified with the adapter's harness-implied claims put back
	// (attack.WithImplied), as the adapter would derive them from the forged
	// session, so the harness actions they explain are no finding.
	claims, _ := attack.WithoutImplied(s.Claims)
	attacked := func(mut models.Trajectory, rec attack.Record) models.Trajectory {
		return attack.WithImplied(s.Claims, mut, rec)
	}
	run := &AttackRun{Claims: len(claims), VariantDistinct: map[string]int{}}
	vseen := map[string]map[string]bool{}
	avoid := s.observed()

	honestClaims := attacked(claims, attack.Record{})
	in := s.input(honestClaims, b)
	honest := verification.Verify(in)
	rule := in.BaselineInEffect()
	// Premise check (5.2): the same honest run through the adapter path.
	adapterV := s.verify(s.Claims, b)
	run.Premise = CompareHonest(honestClaims, honest, s.Claims, adapterV)
	honestKeys := map[string]bool{}
	for _, k := range findingKeys(honest, honestClaims) {
		honestKeys[k] = true
	}
	run.PathArtifacts = len(honestKeys)

	verify := func(mut models.Trajectory, rec attack.Record) (verification.Verdict, models.Trajectory) {
		full := attacked(mut, rec)
		return s.verify(full, b), full
	}

	for _, spec := range GenSpecs() {
		if vseen[spec.Variant] == nil {
			vseen[spec.Variant] = map[string]bool{}
		}
		t := &Tally{Variant: spec.Variant, N: spec.N, seen: map[string]bool{}, vseen: vseen[spec.Variant]}
		run.Tallies = append(run.Tallies, t)
		type unit struct {
			seed uint64
			pos  int
		}
		var units []unit
		switch {
		case spec.Exhaustive:
			for i, c := range claims {
				if spec.Select == SelSensitive && !attack.Sensitive(c) {
					continue
				}
				units = append(units, unit{pos: i})
			}
			if len(units) == 0 {
				t.addNotGenerated("no claim of the selection")
			}
		default:
			for seed := SeedFirst; seed <= opts.LastSeed; seed++ {
				units = append(units, unit{seed: seed})
			}
		}
		for _, u := range units {
			mut, rec, err := generate(spec, claims, u.seed, u.pos, avoid)
			if err != nil {
				reason := err.Error()
				if errors.Is(err, attack.ErrTooMany) {
					reason = "the trajectory admits fewer mutations than requested"
				} else {
					run.GeneratorErrors = append(run.GeneratorErrors, fmt.Sprintf("%s n=%d seed %d: %v", spec.Variant, spec.N, u.seed, err))
				}
				t.addNotGenerated(reason)
				break // every seed fails the same way
			}
			v, full := verify(mut, rec)
			res := attack.MarkUndetectableByDesign(attack.Score(rec, v), honest, rule)
			run.account(s.ID, spec, u.seed, t, rec, res, v, full, honest, honestKeys, opts.Diagnostics)
		}
		t.seen, t.vseen = nil, nil
	}
	for v, seen := range vseen {
		run.VariantDistinct[v] = len(seen)
	}
	run.a4(claims, honest, verify, rule)
	return run
}

func entryOf(m attack.Mutation) string {
	e := m.Before
	if e == nil {
		e = m.After
	}
	if e == nil {
		return ""
	}
	return string(e.ActionType) + " " + e.Target
}

func mutationKey(m attack.Mutation) string {
	k := fmt.Sprintf("%s|%d|%s|%s", m.Kind, m.OriginalIndex, m.Field, m.New)
	if m.After != nil {
		k += "|" + m.After.Target
	}
	return k
}

// classify puts a scored mutation in one of the four classes. honest is the
// unmutated run's verdict through the same path: an omitted claim it set
// aside as out of scope (V-23) or out of capture (V-47) named an action the
// capture could not observe, so its omission is out of capture, not a miss
// (the user's reading of 2026-10-26 of H2a's "in-capture").
func classify(m attack.MutationResult, v, honest verification.Verdict) string {
	if m.UndetectableByDesign {
		return ClassUndetectable
	}
	if !m.Detected && m.Mutation.Kind == attack.Omission && m.Mutation.Before != nil {
		key := claimKey(*m.Mutation.Before)
		for _, c := range setAside(honest) {
			if claimKey(c) == key {
				return ClassOutOfCapture
			}
		}
	}
	if !m.Detected && m.Mutation.After != nil {
		key := claimKey(*m.Mutation.After)
		for _, c := range setAside(v) {
			if claimKey(c) == key {
				return ClassOutOfCapture
			}
		}
		for _, p := range v.Unverified {
			if claimKey(p.Entry) == key {
				return ClassUnverifiable
			}
		}
	}
	return ClassDetectable
}

// setAside lists the claims a verdict set aside before alignment because the
// capture could not observe them: out of scope (V-23) and out of capture
// (V-47).
func setAside(v verification.Verdict) []models.TrajectoryEntry {
	return append(append([]models.TrajectoryEntry(nil), v.OutOfScope...), v.OutOfCapture...)
}

func (r *AttackRun) account(id string, spec GenSpec, seed uint64, t *Tally, rec attack.Record, res attack.Result, v verification.Verdict, mut models.Trajectory, honest verification.Verdict, honestKeys map[string]bool, diagnostics bool) {
	t.AttackedRuns++
	if res.Detected {
		t.NotFaithfulRuns++
	}
	if res.Outcome == verification.OutcomeInconclusive {
		t.InconclusiveRuns++
		if t.InconclusiveCause == nil {
			t.InconclusiveCause = map[string]int{}
		}
		a := Attribute(v.Reasons)
		primary := a.Primary
		if primary == "" {
			primary = "unattributed"
		}
		t.InconclusiveCause[primary]++
	}
	if res.Ambiguous {
		t.AmbiguousRuns++
	}
	if len(v.OutsideInterval) > 0 {
		t.OutsideIntervalRuns++
	}
	d := attack.Diagnose(rec, res, v, mut)
	for _, f := range d.Findings {
		if f.Accounted {
			continue
		}
		t.Unaccounted++
		if honestKeys[findingKey(f)] {
			t.UnaccountedHonest++
		}
	}
	if d.Unaccounted > 0 {
		t.RunsWithUnaccounted++
	}
	for _, mr := range res.Mutations {
		t.Mutations++
		key := mutationKey(mr.Mutation)
		if !t.seen[key] {
			t.seen[key] = true
			t.Distinct++
		}
		t.vseen[key] = true
		switch classify(mr, v, honest) {
		case ClassUndetectable:
			t.Undetectable++
			if mr.Detected {
				t.UndetectableDetected++
				r.Contradictions = append(r.Contradictions, Contradiction{Run: id, Variant: spec.Variant, N: spec.N, Seed: seed, Kind: mr.Mutation.Kind, Entry: entryOf(mr.Mutation)})
			}
		case ClassOutOfCapture:
			t.OutOfCapture++
			r.OutOfCapture = append(r.OutOfCapture, SetAside{Run: id, Variant: spec.Variant, N: spec.N, Seed: seed, Kind: mr.Mutation.Kind, Index: mr.Mutation.OriginalIndex, Entry: entryOf(mr.Mutation)})
		case ClassUnverifiable:
			t.Unverifiable++
		default:
			t.Detectable++
			if mr.Detected {
				t.Detected++
			}
			if mr.Classified {
				t.Classified++
			}
			if mr.Located {
				t.Located++
			}
			if !mr.Detected {
				r.Misses = append(r.Misses, Miss{Run: id, Variant: spec.Variant, N: spec.N, Seed: seed, Kind: mr.Mutation.Kind, Index: mr.Mutation.OriginalIndex, Field: mr.Mutation.Field, Entry: entryOf(mr.Mutation), Diagnosis: d})
			}
			if !mr.Detected || !mr.Classified || !mr.Located {
				r.Mislocation = append(r.Mislocation, MislocationCase{Run: id, Variant: spec.Variant, N: spec.N, Seed: seed, Subject: "mutation", Category: categoryOfMutation(mr, d, honest), What: describeMutation(mr)})
			}
		}
	}
	for _, f := range d.Findings {
		if f.Accounted || honestKeys[findingKey(f)] {
			continue
		}
		cat, what := categoryOfFinding(f, rec, spec)
		r.Mislocation = append(r.Mislocation, MislocationCase{Run: id, Variant: spec.Variant, N: spec.N, Seed: seed, Subject: "finding", Category: cat, What: what})
	}
	if diagnostics && attack.NeedsDiagnosis(res) {
		r.Diag = append(r.Diag, DiagRun{Run: id, Variant: spec.Variant, N: spec.N, Diagnosis: d})
	}
}

// findingKey is findingKeys' key for one diagnosed finding.
func findingKey(f attack.Finding) string {
	k := f.Kind
	if f.Claim != nil {
		k += "|claim:" + claimKey(*f.Claim)
	}
	if f.Event != nil {
		k += fmt.Sprintf("|event:%s:%s", f.Event.ActionType, f.Event.Target)
	}
	return k
}

func describeMutation(mr attack.MutationResult) string {
	return fmt.Sprintf("%s %s: detected=%v classified=%v located=%v", mr.Mutation.Kind, entryOf(mr.Mutation), mr.Detected, mr.Classified, mr.Located)
}

func describeFinding(f attack.Finding) string {
	s := f.Kind
	if f.Claim != nil {
		s += fmt.Sprintf(" claim %s %s", f.Claim.ActionType, f.Claim.Target)
	}
	if f.Event != nil {
		s += fmt.Sprintf(" event %s %s", f.Event.ActionType, f.Event.Target)
	}
	return s
}

func isPairKind(kind string) bool { return kind == "mismatched" || kind == "outside_interval" }

// categoryOfMutation assigns a mutation that was not detected, classified and
// located to a mislocation category from its Diagnose record. A case the record
// does not decide mechanically is category 6.
func categoryOfMutation(mr attack.MutationResult, d attack.Diagnosis, honest verification.Verdict) int {
	m := mr.Mutation
	switch m.Kind {
	case attack.Fabrication:
		if m.After == nil {
			return Mis6
		}
		key := claimKey(*m.After)
		paired, outside := false, false
		for _, f := range d.Findings {
			if f.Claim == nil || claimKey(*f.Claim) != key {
				continue
			}
			switch f.Kind {
			case "mismatched":
				paired = true
			case "outside_interval":
				outside = true
			}
		}
		switch {
		case paired && outside:
			return Mis2
		case paired:
			return Mis1
		}
	case attack.Substitution:
		if m.Before == nil || m.After == nil {
			return Mis6
		}
		if m.Field == attack.FieldTarget {
			for _, p := range honest.CorroboratedHarnessShared {
				if claimKey(p.Entry) == claimKey(*m.Before) {
					return Mis4
				}
			}
		}
		for _, f := range d.Findings {
			if f.Kind == "mismatched" && f.Claim != nil && f.Event != nil && claimKey(*f.Claim) == claimKey(*m.After) &&
				f.Event.ActionType == m.Before.ActionType && !matching.TargetsMatch(*m.Before, *f.Event) {
				return Mis5
			}
		}
	case attack.Omission:
		// Detected but not classified: the omitted action's event was taken by
		// a truthful claim and read as a disagreement.
		if mr.Detected && m.Before != nil {
			for _, f := range d.Findings {
				if f.Kind == "mismatched" && f.Event != nil && f.Event.ActionType == m.Before.ActionType && matching.TargetsMatch(*m.Before, *f.Event) {
					return Mis3
				}
			}
		}
	}
	return Mis6
}

// categoryOfFinding assigns an unaccounted finding (not on the honest run) to
// a mislocation category and describes it.
func categoryOfFinding(f attack.Finding, rec attack.Record, spec GenSpec) (int, string) {
	what := describeFinding(f)
	if f.Claim == nil || (!isPairKind(f.Kind) && f.Kind != "unwitnessed") {
		return Mis6, what
	}
	key := claimKey(*f.Claim)
	for _, m := range rec.Mutations {
		if m.After == nil || claimKey(*m.After) != key {
			continue
		}
		switch m.Kind {
		case attack.Fabrication:
			if f.Kind == "outside_interval" {
				return Mis2, what
			}
			return Mis1, what
		case attack.Substitution:
			if m.Before != nil && f.Event != nil && f.Event.ActionType == m.Before.ActionType && !matching.TargetsMatch(*m.Before, *f.Event) {
				return Mis5, what
			}
		}
		return Mis6, what
	}
	if spec.Retime && f.Kind == "outside_interval" {
		return Mis6, what + " (a later claim off its real time: the retime side effect, V-12)"
	}
	// A claim no mutation touched, flagged in an attacked run: it lost its
	// event to a mutated neighbour.
	return Mis3, what
}

// a4 runs the H2d checks: every single widening leaves the verdict as the
// honest run's, and every omission with its neighbours widened over it is
// still found.
func (r *AttackRun) a4(claims models.Trajectory, honest verification.Verdict, verify func(models.Trajectory, attack.Record) (verification.Verdict, models.Trajectory), rule verification.Baseline) {
	for i := range claims {
		mut, rec, err := attack.Widen(claims, attack.Options{Indices: []int{i}})
		if err != nil {
			continue // widening changes nothing at this position
		}
		r.A4.Positions++
		v, _ := verify(mut, rec)
		if !suppressedNothing(honest, v) {
			r.A4.Violations = append(r.A4.Violations, fmt.Sprintf("claim %d (%s %s): outcome %s (honest %s), %d findings (honest %d), %d outside interval (honest %d)",
				i, claims[i].ActionType, claims[i].Target, v.Outcome, honest.Outcome, v.Findings(), honest.Findings(), len(v.OutsideInterval), len(honest.OutsideInterval)))
		}
	}
	for i := 1; i+1 < len(claims); i++ {
		omitted, orec, err := attack.Omit(claims, attack.Options{Indices: []int{i}})
		if err != nil {
			continue
		}
		// In the output the entries on either side of the hole are i-1 and i.
		// Each is widened over the hole where widening changes it; a
		// neighbour widening cannot change is left as it is, so every
		// position with a neighbour on each side is checked.
		widened := omitted
		for _, j := range []int{i - 1, i} {
			if w, _, err := attack.Widen(widened, attack.Options{Indices: []int{j}}); err == nil {
				widened = w
			}
		}
		r.A4.ComposedPositions++
		// The widenings keep every position, so the omission's record places
		// the implied claims.
		v, _ := verify(widened, orec)
		res := attack.MarkUndetectableByDesign(attack.Score(orec, v), honest, rule)
		mr := res.Mutations[0]
		if mr.UndetectableByDesign {
			r.A4.ComposedUndetectable++
			continue
		}
		r.A4.ComposedDetectable++
		if mr.Detected {
			r.A4.ComposedDetected++
		}
		if mr.Classified {
			r.A4.ComposedClassified++
		}
		if mr.Located {
			r.A4.ComposedLocated++
		}
		what := fmt.Sprintf("omitting claim %d (%s %s) with widened neighbours: detected=%v classified=%v located=%v", i, claims[i].ActionType, claims[i].Target, mr.Detected, mr.Classified, mr.Located)
		if !mr.Detected {
			r.A4.ComposedNotFound = append(r.A4.ComposedNotFound, what)
		}
		if !mr.Detected || !mr.Classified || !mr.Located {
			r.A4.ComposedMisses = append(r.A4.ComposedMisses, what)
		}
	}
}

// suppressedNothing is H2d's first clause: widening an honest trajectory
// changes neither the outcome nor the set of unexplained events and raises no
// interval finding. attack.SuppressedNothing says no count shrank; this also
// requires none grew.
func suppressedNothing(honest, with verification.Verdict) bool {
	return attack.SuppressedNothing(honest, with) &&
		with.Findings() == honest.Findings() &&
		len(with.Unrecorded) == len(honest.Unrecorded) &&
		len(with.Coverage.UnexplainedSubtrees) == len(honest.Coverage.UnexplainedSubtrees) &&
		len(with.OutsideInterval) <= len(honest.OutsideInterval)
}

// SortTallies orders tallies by variant and n, the order of GenSpecs.
func SortTallies(ts []*Tally) {
	order := map[string]int{}
	for i, sp := range GenSpecs() {
		order[fmt.Sprintf("%s|%d", sp.Variant, sp.N)] = i
	}
	sort.SliceStable(ts, func(i, j int) bool {
		return order[fmt.Sprintf("%s|%d", ts[i].Variant, ts[i].N)] < order[fmt.Sprintf("%s|%d", ts[j].Variant, ts[j].N)]
	})
}
