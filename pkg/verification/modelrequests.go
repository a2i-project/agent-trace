package verification

import (
	"fmt"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// ModelRequest is one request the harness's record says it sent to its
// model API (P-43): the input items of one model call, as the adapter reads
// them from its record, each digested as the net probe digests a captured
// request's items (tlsparse.ResponsesItemDigest). A harness that sends
// incremental requests records, per call, only the items it added since
// the response it continues. Never a claim, never aligned.
type ModelRequest struct {
	// Index is the request's position in the record, from 0.
	Index int `json:"index"`
	// PreviousResponseID is the response the request continues, as the
	// record names it; "" for a request that continues none.
	PreviousResponseID string `json:"previous_response_id,omitempty"`
	// ResponseID is the response the record says the request got; "" when
	// the record names none.
	ResponseID string                   `json:"response_id,omitempty"`
	Items      []models.ModelItemDigest `json:"items"`
	Timestamp  time.Time                `json:"timestamp"`
}

// ModelRequestCheck is what the capture says of one recorded request.
type ModelRequestCheck struct {
	Request ModelRequest `json:"request"`
	// Corroborated is true when exactly one captured request continues the
	// same response and its items equal the record's, in order, by type,
	// role, call id and hash. It says the request the harness sent at that
	// point carried what its record says, item for item.
	Corroborated bool `json:"corroborated"`
	// Event is the captured request the check joined, when exactly one
	// continues the same response.
	Event *models.GroundTruthEvent `json:"event,omitempty"`
	// Missing are the record's items the captured request does not carry,
	// Extra the captured request's items the record does not hold.
	Missing []models.ModelItemDigest `json:"missing,omitempty"`
	Extra   []models.ModelItemDigest `json:"extra,omitempty"`
	// ResponseSeen is true when a WebSocket turn of the capture named the
	// response the record says the request got.
	ResponseSeen bool `json:"response_seen"`
	// Reason says why the request is not corroborated. Empty when it is.
	Reason string `json:"reason,omitempty"`
}

// ModelRequestReport is the check of the model requests (P-43): each
// recorded request against the captured ones, and the captured requests no
// recorded request accounts for. Reported, never a finding, and no effect
// on the outcome until the check has been measured on live captures.
type ModelRequestReport struct {
	// Method is the content method the adapter says carries its model
	// traffic, and State that method's request state in the capture.
	Method string              `json:"method"`
	State  string              `json:"state"`
	Checks []ModelRequestCheck `json:"checks"`
	// Unrecorded are captured requests (with a digest) that no recorded
	// request joined: a request the harness sent that its record does not
	// show, or one whose record differs in the response it continues.
	Unrecorded []models.GroundTruthEvent `json:"unrecorded,omitempty"`
}

// Corroborated counts the corroborated checks.
func (r *ModelRequestReport) Corroborated() int {
	n := 0
	for _, c := range r.Checks {
		if c.Corroborated {
			n++
		}
	}
	return n
}

// checkModelRequests joins each recorded request to the captured requests
// that continue the same response (P-43). Nil when the adapter records no
// request.
func checkModelRequests(reqs []ModelRequest, method string, ground models.GroundTruth, cov *models.Coverage) *ModelRequestReport {
	if len(reqs) == 0 {
		return nil
	}
	rep := &ModelRequestReport{Method: method, State: models.ContentIdentityOnly}
	if cov != nil {
		rep.State, _ = cov.Probes["net"].MethodContent(method)
	}
	byPrev := map[string][]int{}
	var captured []models.GroundTruthEvent
	seen := map[string]bool{}
	for _, e := range ground {
		if e.ActionType == models.NetRequest && e.ModelRequest != nil {
			byPrev[e.ModelRequest.PreviousResponseID] = append(byPrev[e.ModelRequest.PreviousResponseID], len(captured))
			captured = append(captured, e)
		}
		if e.Response != nil && e.Response.WebSocket != nil {
			for _, id := range e.Response.WebSocket.ResponseIDs {
				seen[id] = true
			}
		}
	}
	used := make([]bool, len(captured))
	for _, r := range reqs {
		chk := ModelRequestCheck{Request: r, ResponseSeen: r.ResponseID != "" && seen[r.ResponseID]}
		cands := byPrev[r.PreviousResponseID]
		var free []int
		for _, i := range cands {
			if !used[i] {
				free = append(free, i)
			}
		}
		switch {
		case rep.State != models.ContentActive:
			chk.Reason = fmt.Sprintf("the capture did not read requests of content method %s (%s)", method, rep.State)
		case len(free) == 0 && r.PreviousResponseID == "":
			chk.Reason = "no captured request continues no response"
		case len(free) == 0:
			chk.Reason = fmt.Sprintf("no captured request continues response %s", r.PreviousResponseID)
		default:
			// Among several requests continuing the same response (a
			// retry), the first with the record's items wins; with none,
			// the first is compared.
			pick := free[0]
			for _, i := range free {
				if m, x := diffItems(r.Items, captured[i].ModelRequest.Items); len(m) == 0 && len(x) == 0 && sameOrder(r.Items, captured[i].ModelRequest.Items) {
					pick = i
					break
				}
			}
			used[pick] = true
			e := captured[pick]
			chk.Event = &e
			chk.Missing, chk.Extra = diffItems(r.Items, e.ModelRequest.Items)
			switch {
			case e.ModelRequest.Truncated:
				chk.Reason = "the captured request held more items than the digest keeps"
			case len(chk.Missing) > 0 || len(chk.Extra) > 0:
				chk.Reason = fmt.Sprintf("the captured request lacks %d of the record's items and carries %d it does not hold", len(chk.Missing), len(chk.Extra))
			case !sameOrder(r.Items, e.ModelRequest.Items):
				chk.Reason = "the captured request carries the record's items in another order"
			default:
				chk.Corroborated = true
			}
		}
		rep.Checks = append(rep.Checks, chk)
	}
	if rep.State == models.ContentActive {
		for i, e := range captured {
			if !used[i] {
				rep.Unrecorded = append(rep.Unrecorded, e)
			}
		}
	}
	return rep
}

func itemKey(d models.ModelItemDigest) string {
	return strings.Join([]string{d.Type, d.Role, d.CallID, d.Hash}, "\x00")
}

// diffItems returns the items of want missing from got and those of got
// not in want, as multisets.
func diffItems(want, got []models.ModelItemDigest) (missing, extra []models.ModelItemDigest) {
	count := map[string]int{}
	for _, d := range got {
		count[itemKey(d)]++
	}
	for _, d := range want {
		if count[itemKey(d)] > 0 {
			count[itemKey(d)]--
		} else {
			missing = append(missing, d)
		}
	}
	left := map[string]int{}
	for _, d := range want {
		left[itemKey(d)]++
	}
	for _, d := range got {
		if left[itemKey(d)] > 0 {
			left[itemKey(d)]--
		} else {
			extra = append(extra, d)
		}
	}
	return missing, extra
}

func sameOrder(a, b []models.ModelItemDigest) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if itemKey(a[i]) != itemKey(b[i]) {
			return false
		}
	}
	return true
}
