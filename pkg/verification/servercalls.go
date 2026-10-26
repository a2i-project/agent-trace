package verification

import (
	"fmt"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// ServerCall is a tool call the harness's model API ran on its own side, such
// as Claude Code's WebSearch (I-16): the host sees no action of it, only the
// model API's response. The adapter reads it from the session; it is never a
// claim, never aligned, and never changes the outcome (V-45).
type ServerCall struct {
	// Tool and ID name the call as the session does.
	Tool string `json:"tool"`
	ID   string `json:"id"`
	// RequestID is the request id the session records for the call: in a
	// Claude Code transcript the requestId of the assistant record that holds
	// the tool_use, the model API response that issued the call.
	RequestID string `json:"request_id,omitempty"`
	// Host is the model API host the harness sent that request to, as the
	// adapter declares it.
	Host      string    `json:"host"`
	Timestamp time.Time `json:"timestamp"`
}

// ServerCallCheck is what the capture says of one server-side call (V-45).
type ServerCallCheck struct {
	Call ServerCall `json:"call"`
	// Corroborated is true when exactly one net_response of the agent's own
	// process carries the call's request id and that response answers a
	// request to the call's host, has status 200, ended by its framing with
	// no byte missed, is an event stream counted to its end, and the capture
	// validated its response reading. It says the response that issued the
	// call was received whole, nothing about the call's query or results.
	Corroborated bool `json:"corroborated"`
	// Response is the net_response the request id joined, when exactly one
	// did.
	Response *models.GroundTruthEvent `json:"response,omitempty"`
	// Reason says why the call is not corroborated. Empty when it is.
	Reason string `json:"reason,omitempty"`
}

// checkServerCalls joins each server-side call to the net_response events of
// the agent's own process (level 0) by request id and checks the gate of
// V-45. The join itself, a transcript's request id against a response's
// request-id header, is unverified on a live capture, so every check carries
// the reason it holds or fails and nothing here enters the outcome.
func checkServerCalls(calls []ServerCall, capability []AttributedEvent, cov *models.Coverage) []ServerCallCheck {
	if len(calls) == 0 {
		return nil
	}
	validated := false
	if cov != nil {
		validated = cov.Probes["net"].Responses == models.ContentActive
	}
	byID := map[string][]models.GroundTruthEvent{}
	for _, a := range capability {
		e := a.Event
		if e.ActionType != models.NetResponse || e.Response == nil || e.Response.RequestID == "" || a.Zone != ZoneAgent {
			continue
		}
		byID[e.Response.RequestID] = append(byID[e.Response.RequestID], e)
	}
	out := make([]ServerCallCheck, 0, len(calls))
	for _, c := range calls {
		chk := ServerCallCheck{Call: c}
		switch matches := byID[c.RequestID]; {
		case c.RequestID == "":
			chk.Reason = "the session records no request id for the call"
		case !validated:
			chk.Reason = "the capture did not validate its reading of responses (net probe responses not active)"
		case len(matches) == 0:
			chk.Reason = "no response read by the agent's own process carries the call's request id"
		case len(matches) > 1:
			chk.Reason = fmt.Sprintf("%d responses read by the agent's own process carry the call's request id", len(matches))
		default:
			e := matches[0]
			chk.Response = &e
			chk.Reason = responseGate(e, c.Host)
			chk.Corroborated = chk.Reason == ""
		}
		out = append(out, chk)
	}
	return out
}

// responseGate is why a joined response does not corroborate a call to host,
// or "" when it does.
func responseGate(e models.GroundTruthEvent, host string) string {
	r := e.Response
	switch {
	case host == "" || !r.Paired || targetHost(e.Target) != host:
		return fmt.Sprintf("the response answers no request to the model API host %q", host)
	case r.Status != 200:
		return fmt.Sprintf("the response has status %d", r.Status)
	case !r.Complete || r.Truncated:
		return "the response did not end by its framing, or bytes of it were missed"
	case r.SSE == nil || r.SSE.Overflow:
		return "the response is not an event stream counted to its end"
	}
	return ""
}

// targetHost is the host of a request target in the form
// models.CanonicalNetTarget writes, "METHOD https://host[:port]path[?query]",
// or "" for any other form. A port other than 443 stays with the host.
func targetHost(target string) string {
	_, rest, ok := strings.Cut(target, " https://")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}
