package codex

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsparse"
)

func respItem(ts, ord, payload string) string {
	return `{"timestamp":"` + ts + `","ordinal":` + ord + `,"type":"response_item","payload":` + payload + `}`
}

func usage(ts, ord, th, id string) string {
	return `{"timestamp":"` + ts + `","ordinal":` + ord + `,"type":"token_usage_record","payload":{"response_id":"` + id + `","thread_id":"` + th + `","turn_id":"t1","usage":{}}}`
}

func digest(t *testing.T, payload string) models.ModelItemDigest {
	t.Helper()
	d, err := tlsparse.ResponsesItemDigest([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return models.ModelItemDigest{Type: d.Type, Role: d.Role, CallID: d.CallID, Hash: d.Hash}
}

// Each token_usage_record ends a model request: the items the harness
// sends recorded since the previous one (tool outputs, user, developer and
// system messages, additional_tools), continuing the response the previous
// one named. The model's own items (reasoning, calls, assistant messages)
// are not sent. A subagent's replayed history is skipped, and its requests
// follow the main thread's (I-91).
func TestParseReadsTheModelRequests(t *testing.T) {
	dir := t.TempDir()
	tools := `{"type":"additional_tools","id":"at_1","role":"developer","tools":[{"name":"exec"}]}`
	dev := `{"type":"message","id":"m_1","role":"developer","content":[{"type":"input_text","text":"rules"}],"internal_chat_message_metadata_passthrough":{"turn_id":"t1"}}`
	user := `{"type":"message","id":"m_2","role":"user","content":[{"type":"input_text","text":"do it"}]}`
	reasoning := `{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"x"}`
	callItem := `{"type":"custom_tool_call","id":"ct_1","call_id":"c1","name":"exec","input":"1","status":"completed","internal_chat_message_metadata_passthrough":{"turn_id":"t1"}}`
	out := `{"type":"custom_tool_call_output","id":"co_1","call_id":"c1","output":"done"}`
	assistant := `{"type":"message","id":"m_3","role":"assistant","content":[{"type":"output_text","text":"ok"}],"status":"completed"}`
	main := write(t, filepath.Join(dir, "task.rollout.jsonl"),
		meta(thread),
		respItem("2026-10-31T23:40:17.000Z", "2", tools),
		respItem("2026-10-31T23:40:17.000Z", "3", dev),
		respItem("2026-10-31T23:40:17.000Z", "4", user),
		respItem("2026-10-31T23:40:18.000Z", "5", reasoning),
		respItem("2026-10-31T23:40:18.000Z", "6", callItem),
		usage("2026-10-31T23:40:18.500Z", "7", thread, "resp_1"),
		respItem("2026-10-31T23:40:19.000Z", "8", out),
		respItem("2026-10-31T23:40:20.000Z", "9", assistant),
		usage("2026-10-31T23:40:20.500Z", "10", thread, "resp_2"),
		itemAt("2026-10-31T23:40:20.600Z", 1793490020600, `{"type":"SubAgentActivity","id":"f1","kind":"started","agent_thread_id":"sub-1"}`),
	)
	subMeta := `{"timestamp":"2026-10-31T23:40:21.000Z","ordinal":0,"type":"session_meta","payload":{"id":"sub-1","session_id":"` + thread + `","cli_version":"0.166.0","subagent_history_start_ordinal":3}}`
	subUser := `{"type":"message","id":"m_9","role":"user","content":[{"type":"input_text","text":"sub task"}]}`
	write(t, filepath.Join(dir, "task.rollout", "subagents", "a.jsonl"),
		subMeta,
		respItem("2026-10-31T23:40:21.000Z", "1", user),
		usage("2026-10-31T23:40:21.000Z", "2", thread, "resp_1"),
		respItem("2026-10-31T23:40:22.000Z", "3", subUser),
		usage("2026-10-31T23:40:23.000Z", "4", "sub-1", "resp_s1"),
	)
	_, rep, err := Adapter{}.Parse(main)
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("%v %v", err, rep.ParseErrors)
	}
	at := func(s string) time.Time { ts, _ := time.Parse(time.RFC3339Nano, s); return ts }
	type req struct {
		Index          int
		Prev, Response string
		Items          []models.ModelItemDigest
		At             time.Time
	}
	var got []req
	for _, r := range rep.ModelRequests {
		got = append(got, req{r.Index, r.PreviousResponseID, r.ResponseID, r.Items, r.Timestamp})
	}
	want := []req{
		{0, "", "resp_1", []models.ModelItemDigest{digest(t, tools), digest(t, dev), digest(t, user)}, at("2026-10-31T23:40:18.500Z")},
		{1, "resp_1", "resp_2", []models.ModelItemDigest{digest(t, out)}, at("2026-10-31T23:40:20.500Z")},
		{2, "", "resp_s1", []models.ModelItemDigest{digest(t, subUser)}, at("2026-10-31T23:40:23.000Z")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("requests\n%+v\nwant\n%+v", got, want)
	}
	if rep.ModelRequestMethod != "tls-rustls-aead" {
		t.Errorf("method %q", rep.ModelRequestMethod)
	}
	// The record's id and internal metadata do not enter the digest.
	if digest(t, dev).Hash != digest(t, strings.Replace(dev, `"id":"m_1",`, "", 1)).Hash {
		t.Error("the digest depends on the record's own id")
	}
}

// A rollout with no token usage record states no request, and no method;
// a record of another thread is a parse error.
func TestParseModelRequestsEdges(t *testing.T) {
	dir := t.TempDir()
	_, rep, err := Adapter{}.Parse(basicRollout(t, dir))
	if err != nil || rep.ModelRequests != nil || rep.ModelRequestMethod != "" {
		t.Errorf("basic rollout: %v, requests %+v, method %q", err, rep.ModelRequests, rep.ModelRequestMethod)
	}
	p := write(t, filepath.Join(dir, "other.rollout.jsonl"), meta(thread), usage("2026-10-31T23:40:18.500Z", "1", "someone-else", "resp_1"))
	_, rep, err = Adapter{}.Parse(p)
	if err != nil || len(rep.ParseErrors) != 1 || rep.ModelRequests != nil {
		t.Errorf("another thread's record: %v, errors %v, requests %+v", err, rep.ParseErrors, rep.ModelRequests)
	}
}
