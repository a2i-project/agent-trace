package verification

import "github.com/agent-trace/agent-trace/pkg/models"

// candidates fills Edit.Candidates for the findings on claims of one lane
// (V-109). A finding is an insertion or a substitution of an ordinary claim
// c. Its candidates are c and every other ordinary claim d of the lane that is
// interchangeable with c and that some minimum-cost alignment leaves unpaired,
// for an insertion, or pairs with the edit's event, for a substitution. Since
// d and c are equal in every field the comparison reads, d's finding there is
// c's finding: the same kind, the same event and the same differing fields.
//
// Most cases need no further run of the program. A twin in c's own segment is
// always a candidate: exchanging two interchangeable members of one block
// changes no cost, so the shown alignment with the two exchanged is a
// minimum-cost alignment that gives d the finding. For an insertion, so is
// every twin in a segment that holds a twin the shown alignment leaves
// unpaired, by the same exchange. Any other twin gets the finding only in an
// alignment that pairs differently, which exists only when Optimal exceeds
// one; then one run of the program with d restricted (forcing), over the band
// of the lane's minimum cost, decides it. Runs are memoised per claim and
// event, so a lane runs the program at most once per twin and event of its
// findings, and a lane without findings on claims that have twins runs it no
// more than before.
func candidates(la *LaneAlignment, claims models.Trajectory, observed models.GroundTruth, ci, ei []int, segs [][]int, opts Options, cost int) error {
	posOf := make(map[int]int, len(ci))
	for p, i := range ci {
		posOf[i] = p
	}
	evOf := make(map[int]int, len(ei))
	for j, e := range ei {
		evOf[e] = j
	}
	segOf := make([]int, len(ci))
	for s, seg := range segs {
		for _, p := range seg {
			segOf[p] = s
		}
	}
	unpaired := map[int]bool{}
	for _, e := range la.Edits {
		if e.Kind == EditInsertion {
			unpaired[posOf[e.ClaimIndex]] = true
		}
	}
	type key struct{ p, event int }
	memo := map[key]bool{}
	reaches := func(q, j int) (bool, error) {
		k := key{q, j}
		if v, ok := memo[k]; ok {
			return v, nil
		}
		_, c, err := runBlocks(LaneAlignment{Lane: la.Lane}, claims, observed, ci, ei, segs, opts, &forcing{p: q, event: j, bound: cost})
		if err != nil {
			return false, err
		}
		memo[k] = c == cost
		return memo[k], nil
	}
	for k := range la.Edits {
		e := &la.Edits[k]
		if e.Kind != EditInsertion && e.Kind != EditSubstitution || implied(*e.Claim) {
			continue
		}
		p := posOf[e.ClaimIndex]
		j := -1
		if e.Kind == EditSubstitution {
			j = evOf[e.EventIndex]
		}
		var twins []int
		for q := range ci {
			if q == p || !implied(claims[ci[q]]) && interchangeable(*e.Claim, claims[ci[q]]) {
				twins = append(twins, q)
			}
		}
		if len(twins) < 2 {
			continue
		}
		// For an insertion, the segments holding a twin left unpaired.
		free := map[int]bool{segOf[p]: true}
		if j < 0 {
			for _, q := range twins {
				if unpaired[q] {
					free[segOf[q]] = true
				}
			}
		}
		var set []int
		for _, q := range twins {
			ok := free[segOf[q]]
			if !ok && la.Optimal > 1 {
				var err error
				if ok, err = reaches(q, j); err != nil {
					return err
				}
			}
			if ok {
				set = append(set, q)
			}
		}
		if len(set) > 1 {
			for _, q := range set {
				e.Candidates = append(e.Candidates, &claims[ci[q]])
			}
		}
	}
	return nil
}

// CandidateSet is a finding on a claim that names several interchangeable
// claims (V-109): an Unwitnessed claim (Finding "unwitnessed") or a
// Mismatched pair (Finding "mismatched", with its Event). Claim is the claim the
// verdict lists, and Claims every claim some minimum-cost alignment gives the
// finding instead, Claim included, in trajectory order.
type CandidateSet struct {
	Finding string                   `json:"finding"`
	Claim   models.TrajectoryEntry   `json:"claim"`
	Event   *models.GroundTruthEvent `json:"event,omitempty"`
	Claims  []models.TrajectoryEntry `json:"claims"`
}

// CandidateSets lists the verdict's findings that name more than one claim,
// lane by lane in the order of the alignment. A finding absent from the list
// names its own claim alone.
func (v Verdict) CandidateSets() []CandidateSet {
	var out []CandidateSet
	for _, la := range v.Alignments {
		for _, e := range la.Edits {
			if len(e.Candidates) == 0 {
				continue
			}
			cs := CandidateSet{Finding: "unwitnessed", Claim: *e.Claim}
			if e.Kind == EditSubstitution {
				cs.Finding = "mismatched"
			}
			if e.Event != nil {
				ev := *e.Event
				cs.Event = &ev
			}
			for _, c := range e.Candidates {
				cs.Claims = append(cs.Claims, *c)
			}
			out = append(out, cs)
		}
	}
	return out
}
