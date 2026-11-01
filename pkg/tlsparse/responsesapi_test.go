package tlsparse

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// An item as a harness records it (with its id, status and internal
// metadata, members in another order and white space) hashes as the same
// item sent without them.
func TestResponsesItemHash_Canonical(t *testing.T) {
	sent := `{"type":"custom_tool_call_output","call_id":"call_1","output":[{"type":"input_text","text":"a <b> & é"}]}`
	recorded := `{ "id": "ctco_9", "internal_chat_message_metadata_passthrough": {"turn_id": "t"},
		"output": [ {"text": "a <b> & é", "type": "input_text"} ], "status": "completed",
		"call_id": "call_1", "type": "custom_tool_call_output" }`
	a, err := ResponsesItemHash(json.RawMessage(sent))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ResponsesItemHash(json.RawMessage(recorded))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("hashes differ: %s vs %s", a, b)
	}
	c, _ := ResponsesItemHash(json.RawMessage(`{"type":"custom_tool_call_output","call_id":"call_1","output":[{"type":"input_text","text":"other"}]}`))
	if c == a {
		t.Error("another output hashes the same")
	}
	// Only top-level bookkeeping is dropped: a nested "id" is content.
	n1, _ := ResponsesItemHash(json.RawMessage(`{"type":"x","v":{"id":1}}`))
	n2, _ := ResponsesItemHash(json.RawMessage(`{"type":"x","v":{"id":2}}`))
	if n1 == n2 {
		t.Error("a nested id was dropped")
	}
	if _, err := ResponsesItemHash(json.RawMessage(`{"a":1} {}`)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestParseResponsesRequest(t *testing.T) {
	item := `{"type":"function_call_output","call_id":"c9","output":"ok"}`
	h, _ := ResponsesItemHash(json.RawMessage(item))
	msg := `{"type":"input_text","role":"user","content":[{"type":"input_text","text":"hi"}]}`
	hm, _ := ResponsesItemHash(json.RawMessage(msg))
	r, ok := ParseResponsesRequest([]byte(`{"type":"response.create","model":"m","previous_response_id":"resp_1","input":[` + item + `,` + msg + `],"tools":[]}`))
	if !ok {
		t.Fatal("not parsed")
	}
	want := &ResponsesRequest{Type: "response.create", PreviousResponseID: "resp_1", Items: []ResponsesItem{
		{Type: "function_call_output", CallID: "c9", Hash: h},
		{Type: "input_text", Role: "user", Hash: hm},
	}}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("%+v, want %+v", r, want)
	}
	if r, ok := ParseResponsesRequest([]byte(`{"type":"response.create","input":"hello"}`)); !ok || len(r.Items) != 1 || r.Items[0].Type != "(text)" || r.PreviousResponseID != "" {
		t.Errorf("string input: %+v %v", r, ok)
	}
	for _, bad := range []string{`{"type":"response.cancel"}`, `[]`, `not json`, `{"type":"response.create","input":5}`, `{"type":"response.create","input":[1]}`} {
		if _, ok := ParseResponsesRequest([]byte(bad)); ok {
			t.Errorf("%s parsed", bad)
		}
	}
}

// A client stream keeps whole text messages up to KeepText for the digest,
// and a server message names its response.
func TestWSStream_KeepTextAndResponseID(t *testing.T) {
	s := NewWSStream(true)
	s.KeepText = 16
	var bodies []string
	emit := func(m *WSMessage) { bodies = append(bodies, string(m.Body)) }
	_ = s.Feed(wsFrame(false, WSText, true, []byte("0123456789")), 0, time.Now(), emit, nil)
	_ = s.Feed(wsFrame(true, WSContinuation, true, []byte("abc")), 0, time.Now(), emit, nil)
	_ = s.Feed(wsFrame(true, WSText, true, []byte("0123456789abcdefg")), 0, time.Now(), emit, nil)
	if !reflect.DeepEqual(bodies, []string{"0123456789abc", ""}) {
		t.Errorf("bodies %q, want the first whole and the second (17 bytes) dropped", bodies)
	}
	srv := NewWSStream(false)
	var id string
	_ = srv.Feed(wsFrame(true, WSText, false, []byte(`{"type":"response.created","sequence_number":0,"response":{"object":"response","usage":{"id":"no"},"id":"resp_7"}}`)), 0, time.Now(), func(m *WSMessage) { id = m.ResponseID }, nil)
	if id != "resp_7" {
		t.Errorf("response id %q", id)
	}
}
