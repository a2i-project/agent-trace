package tlsparse

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// A request to the OpenAI Responses API over a WebSocket is one client
// message, a JSON object whose "type" is "response.create", naming the
// response it continues ("previous_response_id") and carrying its "input"
// items (P-42). The net probe keeps a digest of it, never the plaintext
// (N-D3): per item its type, role, call id and the hash ResponsesItemHash
// gives, which an adapter computes the same way from the items its record
// holds, so that each captured request can be checked against the request
// the record says was sent (P-43).

// Bounds of the digest.
const (
	maxResponsesItems = 4096
	maxResponsesField = 256
)

// ResponsesRequest is the digest of one Responses API request.
type ResponsesRequest struct {
	Type               string
	PreviousResponseID string
	Items              []ResponsesItem
	// Truncated is set when the input held more than 4096 items; Items
	// holds the first 4096.
	Truncated bool
}

// ResponsesItem is the digest of one input item.
type ResponsesItem struct {
	Type   string // the item's "type"; "(text)" for an input given as a string
	Role   string // a message's "role"
	CallID string // a tool output's "call_id"
	Hash   string // ResponsesItemHash of the item
}

// ParseResponsesRequest reads body as a Responses API request sent over a
// WebSocket. ok is false unless body is a JSON object whose "type" is
// "response.create".
func ParseResponsesRequest(body []byte) (*ResponsesRequest, bool) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, false
	}
	var typ string
	if json.Unmarshal(top["type"], &typ) != nil || typ != "response.create" {
		return nil, false
	}
	r := &ResponsesRequest{Type: typ}
	r.PreviousResponseID = boundedString(top["previous_response_id"])
	raw := bytes.TrimSpace(top["input"])
	switch {
	case len(raw) == 0 || bytes.Equal(raw, []byte("null")):
	case raw[0] == '"':
		h, err := ResponsesItemHash(raw)
		if err != nil {
			return nil, false
		}
		r.Items = []ResponsesItem{{Type: "(text)", Hash: h}}
	default:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, false
		}
		if len(items) > maxResponsesItems {
			items, r.Truncated = items[:maxResponsesItems], true
		}
		for _, it := range items {
			d, err := ResponsesItemDigest(it)
			if err != nil {
				return nil, false
			}
			r.Items = append(r.Items, d)
		}
	}
	return r, true
}

// ResponsesItemDigest is the digest of one Responses API item, as the
// probe records it for a captured request and as an adapter computes it
// for an item of its record.
func ResponsesItemDigest(item json.RawMessage) (ResponsesItem, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(item, &fields); err != nil {
		return ResponsesItem{}, err
	}
	h, err := ResponsesItemHash(item)
	if err != nil {
		return ResponsesItem{}, err
	}
	return ResponsesItem{Type: boundedString(fields["type"]), Role: boundedString(fields["role"]), CallID: boundedString(fields["call_id"]), Hash: h}, nil
}

// ResponsesItemHash is "sha256:<hex>" of an item's canonical JSON: the item
// with its "id" and "status" members and every member whose name begins
// with "internal_" removed at the top level (identifiers and bookkeeping a
// harness may add to its record or leave out of the request), object
// members sorted by name, no insignificant white space, numbers as written,
// and strings escaped as encoding/json escapes them without HTML escaping.
// A string item hashes as its canonical JSON string.
func ResponsesItemHash(item json.RawMessage) (string, error) {
	d := json.NewDecoder(bytes.NewReader(item))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return "", err
	}
	if d.More() {
		return "", errors.New("tlsparse: trailing data after a JSON item")
	}
	if m, ok := v.(map[string]any); ok {
		delete(m, "id")
		delete(m, "status")
		for k := range m {
			if strings.HasPrefix(k, "internal_") {
				delete(m, k)
			}
		}
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// boundedString is the JSON string raw holds, "" when it is not a string
// or longer than 256 bytes or not printable.
func boundedString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil || len(s) > maxResponsesField || !printable(s) {
		return ""
	}
	return s
}
