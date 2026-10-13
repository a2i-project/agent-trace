package gemini

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// walCopy returns a directory holding a copy of the strace tools conversation
// in write-ahead-log mode whose log still holds a change the database file
// does not: every step after the second tool call deleted. It is the state agy
// leaves while it runs, or when it exits without a checkpoint.
func walCopy(t *testing.T) string {
	t.Helper()
	live := t.TempDir()
	src, err := os.ReadFile(filepath.Join(realDir, "tools.conversation.db"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(live, "c.db")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	for _, q := range []string{"pragma journal_mode=wal", "pragma wal_autocheckpoint=0", "delete from steps where idx > 4"} {
		if _, err := conn.ExecContext(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// Copied while the connection is open, so the log is not yet checkpointed
	// into the database file.
	out := t.TempDir()
	for _, suffix := range []string{"", "-wal"} {
		b, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "c.db"+suffix), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if fi, err := os.Stat(filepath.Join(out, "c.db-wal")); err != nil || fi.Size() == 0 {
		t.Fatalf("the log is empty: %v", err)
	}
	return out
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n []string
	for _, e := range es {
		n = append(n, e.Name())
	}
	sort.Strings(n)
	return n
}

// Parse reads what only the write-ahead log holds, and writes nothing next to
// the database it reads (I-51).
func TestParseReadsTheLogAndLeavesTheDirectoryAlone(t *testing.T) {
	dir := walCopy(t)
	path := filepath.Join(dir, "c.db")
	before := names(t, dir)
	if !(Adapter{}).Detect(path) {
		t.Fatal("Detect refused a database in write-ahead-log mode")
	}
	tr, rep, err := Adapter{}.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	// The database file alone holds nine claims (TestARealConversationParses).
	if rep.ToolCalls != 2 || len(tr) != 2 || tr[0].Target != "echo hi" || tr[1].Target != "/ws/1/b.txt" {
		t.Errorf("Parse read %d tool calls, claims %+v; want the two the log leaves", rep.ToolCalls, tr)
	}
	if after := names(t, dir); len(after) != len(before) {
		t.Errorf("the directory held %v and holds %v after Parse", before, after)
	}
}

// A session in a directory the reader may not write still parses.
func TestParseReadsADatabaseInAReadOnlyDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	dir := walCopy(t)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	path := filepath.Join(dir, "c.db")
	if !(Adapter{}).Detect(path) {
		t.Fatal("Detect refused a database in a read-only directory")
	}
	if _, _, err := (Adapter{}).Parse(path); err != nil {
		t.Fatal(err)
	}
}
