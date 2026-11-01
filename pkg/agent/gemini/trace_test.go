package gemini

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The declaration names every conversation database of the home as a main
// session file and covers nothing, so no event reads as tampering until
// O-37 is decided (I-102).
func TestTraceDeclaresTheConversationDatabases(t *testing.T) {
	const id = "0b18d7d3-41b4-4dfe-b649-e8ba776c383a"
	conv := "/home/u/.gemini/antigravity-cli/conversations/"
	d := Adapter{}.Trace("/ws/basic", "/home/u")
	if d == nil || d.Covers != nil {
		t.Fatalf("declaration %+v, want Main only", d)
	}
	for path, want := range map[string]bool{
		conv + id + ".db":     true,
		conv + id + ".db-wal": false,
		conv + id + ".db-shm": false,
		conv + "x.db":         false,
		"/home/u/.gemini/antigravity-cli/conversation_summaries.db":                                false,
		"/home/u/.gemini/antigravity-cli/brain/" + id + "/.system_generated/logs/transcript.jsonl": false,
		"/home/v/.gemini/antigravity-cli/conversations/" + id + ".db":                              false,
		conv + id + ".db (deleted)": false,
	} {
		if got := d.Main(path); got != want {
			t.Errorf("%s: main = %v, want %v", path, got, want)
		}
	}
	d = Adapter{}.Trace("", "")
	if !d.Main("/root/.gemini/antigravity-cli/conversations/"+id+".db") || !d.Main("/home/x/.gemini/antigravity-cli/conversations/"+id+".db") {
		t.Error("without a home, the database under any home should be declared")
	}
	for _, home := range []string{"/etc", "/home/u/", "/home/u/../v"} {
		if (Adapter{}).Trace("/ws", home) != nil {
			t.Errorf("home %q: want no declaration", home)
		}
	}
}

// ReadTrace reads a missing, empty or unreadable database as a trace that
// cannot be verified, never as an error, and hashes an intact one on request
// (V-59).
func TestReadTraceFailsClosed(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.conversation.db")
	garbled := filepath.Join(dir, "garbled.conversation.db")
	_ = os.WriteFile(empty, nil, 0o644)
	_ = os.WriteFile(garbled, []byte("SQLite format 3\x00 but nothing else"), 0o644)
	for path, want := range map[string]verification.TraceState{
		filepath.Join(dir, "gone.conversation.db"): verification.TraceMissing,
		empty:   verification.TraceEmpty,
		garbled: verification.TraceUnparsable,
	} {
		_, _, in, err := agent.ReadTrace(Adapter{}, path, true)
		if err != nil || in.State != want || in.Detail == "" || in.ReadHash != "" {
			t.Errorf("%s: state %q detail %q hash %q err %v, want %q", filepath.Base(path), in.State, in.Detail, in.ReadHash, err, want)
		}
	}
	db := filepath.Join(pairedDir, "basic.conversation.db")
	tr, _, in, err := agent.ReadTrace(Adapter{}, db, true)
	want, _ := content.SHA256File(db)
	if err != nil || in.State != verification.TraceRead || in.ReadHash != want || len(tr) == 0 {
		t.Errorf("intact: state %q hash %q err %v, %d claims", in.State, in.ReadHash, err, len(tr))
	}
}

// On the paired basic capture the declaration finds the database the
// harness wrote and closed with a hash, and changes no verdict.
func TestPairedTheDeclarationChangesNoVerdict(t *testing.T) {
	g := pairedRun(t, "basic")
	tr, _, err := Adapter{}.Parse(filepath.Join(pairedDir, "basic.conversation.db"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := agent.Capture(Adapter{}, "1.3.4", pairedControls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}})
	if err != nil {
		t.Fatal(err)
	}
	in := agent.PrepareWithBaseline(Adapter{}, tr, g, &b, verification.Options{IntervalSlack: 500 * time.Millisecond})
	without := verification.Verify(in)
	in.Trace.Decl = agent.Trace(Adapter{}, g)
	v := verification.Verify(in)
	if len(v.TraceTampering) != 0 || v.Trace.Declared {
		t.Fatalf("tampering %+v, declared %v, want none and no covered paths", v.TraceTampering, v.Trace.Declared)
	}
	if len(v.Trace.Files) != 1 || !strings.HasSuffix(v.Trace.Files[0].Path, ".db") || v.Trace.Files[0].Last == nil ||
		v.Trace.Files[0].Last.ActionType != models.FileClose || v.Trace.Files[0].Last.OutputHash == nil {
		t.Fatalf("trace files %+v, want the database with a hashed last close", v.Trace.Files)
	}
	if v.Outcome != without.Outcome || v.Findings() != without.Findings() || len(v.Reasons) != len(without.Reasons) {
		t.Errorf("with the declaration %v/%d, without %v/%d", v.Outcome, v.Findings(), without.Outcome, without.Findings())
	}
	// The database gone: the run cannot be verified, whatever the probes saw.
	in.Trace.State, in.Trace.Detail = verification.TraceMissing, "gone"
	if v := verification.Verify(in); v.Outcome != verification.OutcomeInconclusive || !strings.Contains(v.Reasons[0], verification.TraceDeletedOrDamaged) {
		t.Errorf("missing: outcome %v, reasons %v", v.Outcome, v.Reasons)
	}
}
