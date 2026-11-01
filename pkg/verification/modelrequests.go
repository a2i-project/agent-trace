package verification

import (
	"fmt"
	"sort"
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
	// WarmUp is the warm-up the joined request continues, when it continues
	// one that itself continued the record's response (V-69).
	WarmUp *models.GroundTruthEvent `json:"warm_up,omitempty"`
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
	// WarmUps are captured requests set aside as warm-ups (V-69): no input
	// item, a turn with no output item, a response no recorded request
	// names and a captured request continues. Never joined, never
	// unrecorded.
	WarmUps []models.GroundTruthEvent `json:"warm_ups,omitempty"`
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
	var captured []models.GroundTruthEvent
	seen := map[string]bool{}
	for _, e := range ground {
		if e.ActionType == models.NetRequest && e.ModelRequest != nil {
			captured = append(captured, e)
		}
		if e.Response != nil && e.Response.WebSocket != nil {
			for _, id := range e.Response.WebSocket.ResponseIDs {
				seen[id] = true
			}
		}
	}
	warm := warmUps(reqs, ground)
	// A recorded request continuing X is joined to the captured requests
	// continuing X and, one hop only, to those continuing the response of a
	// warm-up that itself continued X (V-69).
	byPrev := map[string][]int{}
	via := map[int]int{}
	warmOf := map[string]int{}
	for i, id := range warm {
		warmOf[id] = i
	}
	for i, e := range captured {
		if _, ok := warm[i]; ok {
			continue
		}
		prev := e.ModelRequest.PreviousResponseID
		if w, ok := warmOf[prev]; ok {
			via[i] = w
			prev = captured[w].ModelRequest.PreviousResponseID
		}
		byPrev[prev] = append(byPrev[prev], i)
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
			if w, ok := via[pick]; ok {
				we := captured[w]
				chk.WarmUp = &we
			}
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
			if _, ok := warm[i]; ok {
				rep.WarmUps = append(rep.WarmUps, e)
			} else if !used[i] {
				rep.Unrecorded = append(rep.Unrecorded, e)
			}
		}
	}
	return rep
}

// warmUps finds the captured requests that are warm-ups (V-69), by their
// index among the captured requests with a digest, each with the response
// its turn named. A warm-up carries no input item; its turn, the first
// WebSocket turn after it with its process and target before the next
// request there, names one response, shows no output item event and keeps
// every type name; no recorded request names that response, as the one it
// got or the one it continues; and a captured request continues it.
func warmUps(reqs []ModelRequest, ground models.GroundTruth) map[int]string {
	named := map[string]bool{}
	for _, r := range reqs {
		named[r.ResponseID], named[r.PreviousResponseID] = true, true
	}
	continued := map[string]bool{}
	type ev struct {
		e   models.GroundTruthEvent
		cap int // index among the captured requests, -1 for none
	}
	var evs []ev
	n := 0
	for _, e := range ground {
		switch {
		case e.ActionType == models.NetRequest && e.ModelRequest != nil:
			continued[e.ModelRequest.PreviousResponseID] = true
			evs = append(evs, ev{e, n})
			n++
		case e.ActionType == models.NetRequest, e.Response != nil && e.Response.WebSocket != nil:
			evs = append(evs, ev{e, -1})
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].e.Timestamp.Before(evs[j].e.Timestamp) })
	type stream struct {
		pid    uint32
		target string
	}
	// open is the captured request of each stream still waiting for its
	// turn.
	open := map[stream]int{}
	out := map[int]string{}
	for _, x := range evs {
		k := stream{x.e.PID, x.e.Target}
		if x.e.ActionType == models.NetRequest {
			if x.cap >= 0 && len(x.e.ModelRequest.Items) == 0 && !x.e.ModelRequest.Truncated {
				open[k] = x.cap
			} else {
				delete(open, k)
			}
			continue
		}
		i, ok := open[k]
		if !ok {
			continue
		}
		delete(open, k)
		ws := x.e.Response.WebSocket
		if len(ws.ResponseIDs) != 1 || outputItems(ws.Types) {
			continue
		}
		if id := ws.ResponseIDs[0]; id != "" && !named[id] && continued[id] {
			out[i] = id
		}
	}
	return out
}

// outputItems is true when a turn's message types show an output item, or
// may: the summary counted some types under "(other)".
func outputItems(types map[string]int) bool {
	for t := range types {
		if t == "(other)" || strings.HasPrefix(t, "response.output_item.") {
			return true
		}
	}
	return false
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
