package codex

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsparse"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// Codex sends each model request over its WebSocket as an incremental
// Responses API request: it names the response it continues and carries
// only the items added since (N-41, P-42). The rollout records those items
// as response_item records and each response the model API returned as a
// token_usage_record naming its id. A thread's model requests are read
// from its own records in order (I-91): the items recorded since the
// previous token_usage_record that the harness sends rather than the model
// returns (the tool outputs, whose type ends in "_output", the user,
// developer and system messages, and the additional_tools record) are the
// request the next token_usage_record answered, continuing the response
// the previous one named. An agent_message, the message another agent
// sent the thread, is sent too (I-97).

// modelRequestMethod is the content method that carries Codex's model
// traffic: its native executable's rustls (N-39).
const modelRequestMethod = "tls-rustls-aead"

// sentRoles are the message roles the harness sends; the assistant's
// messages are the model's output, which the response it continues holds.
var sentRoles = map[string]bool{"user": true, "developer": true, "system": true}

// requestReader collects one thread's model requests.
type requestReader struct {
	pending  []json.RawMessage
	previous string
	requests []verification.ModelRequest
}

// item takes one response_item payload of the given type and role.
func (r *requestReader) item(typ, role string, payload json.RawMessage) {
	switch {
	case strings.HasSuffix(typ, "_output"):
		r.pending = append(r.pending, withoutEmptyText(payload))
	case typ == "additional_tools" || typ == "agent_message" || (typ == "message" && sentRoles[role]):
		r.pending = append(r.pending, append(json.RawMessage(nil), payload...))
	}
}

// withoutEmptyText is a tool output's payload as Codex sends it: its
// "output" list without the parts that are exactly an empty input_text
// ({"type":"input_text","text":""}), which Codex leaves out of the request
// although its record keeps them (I-97). A payload with no such part is
// returned as recorded.
func withoutEmptyText(payload json.RawMessage) json.RawMessage {
	keep := append(json.RawMessage(nil), payload...)
	var fields map[string]json.RawMessage
	var parts []json.RawMessage
	if json.Unmarshal(payload, &fields) != nil || json.Unmarshal(fields["output"], &parts) != nil {
		return keep
	}
	kept := parts[:0:0]
	for _, p := range parts {
		var part map[string]json.RawMessage
		var typ, text string
		if json.Unmarshal(p, &part) == nil && len(part) == 2 &&
			json.Unmarshal(part["type"], &typ) == nil && typ == "input_text" &&
			json.Unmarshal(part["text"], &text) == nil && text == "" {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) == len(parts) {
		return keep
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return keep
	}
	fields["output"] = out
	if b, err := json.Marshal(fields); err == nil {
		return b
	}
	return keep
}

// response ends the pending request at a token_usage_record naming the
// response it got.
func (r *requestReader) response(id string, at time.Time) error {
	req := verification.ModelRequest{PreviousResponseID: r.previous, ResponseID: id, Items: []models.ModelItemDigest{}, Timestamp: at}
	for _, raw := range r.pending {
		d, err := tlsparse.ResponsesItemDigest(raw)
		if err != nil {
			return fmt.Errorf("an item of the request answered by %s: %v", id, err)
		}
		req.Items = append(req.Items, models.ModelItemDigest{Type: d.Type, Role: d.Role, CallID: d.CallID, Hash: d.Hash})
	}
	r.requests = append(r.requests, req)
	r.pending, r.previous = nil, id
	return nil
}

// tokenUsage is the part of a token_usage_record the requests read.
type tokenUsage struct {
	ResponseID string `json:"response_id"`
	ThreadID   string `json:"thread_id"`
}
