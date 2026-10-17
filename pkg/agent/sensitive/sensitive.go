// Package sensitive snapshots the harness's security-sensitive files at the
// start and the stop of a capture and records what changed between the two,
// by structure and never by content (V-40). The adapters declare the files
// (agent.SensitiveDeclarer, I-59); cmd/watch, which runs as root, takes the
// snapshots.
//
// A JSON file is summarised as a map from key path to a hash of the value
// there, with a list held as the set of its entries' hashes, so an entry
// added to a permission list shows as an added entry and a reordering shows
// as nothing. Any other file is summarised by one hash of its bytes. The
// hashes are HMAC-SHA256 under a key drawn at random for each capture and
// never written: they are compared between the two ends of one capture
// only, and without the key a hash cannot be matched against a guessed
// value, even a low-entropy one such as true or false. What the capture
// records is the state and digest of each end and the list of changes, each
// a key path and a kind; never a value.
package sensitive

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// MaxBytes is the largest file a snapshot reads. A larger one is recorded as
// too large, not read: the declared files are small (Claude Code's
// ~/.claude.json, the largest, held about 120 KB on the development machine
// on 2026-10-17).
const MaxBytes = 16 << 20

// The prefixes a declaration starts with.
const (
	// HomePrefix: the file is under the home of the user the agent runs as.
	HomePrefix = "~/"
	// WorkspacePrefix: the file is under the watched workspace.
	WorkspacePrefix = "{workspace}/"
)

// Resolve turns a declared file into a path. It reports false for a
// declaration with neither prefix, for one whose base is unknown (an empty
// home or workspace), and for one that leaves its base after cleaning.
func Resolve(declared, home, workspace string) (string, bool) {
	var base, rest string
	switch {
	case strings.HasPrefix(declared, HomePrefix):
		base, rest = home, strings.TrimPrefix(declared, HomePrefix)
	case strings.HasPrefix(declared, WorkspacePrefix):
		base, rest = workspace, strings.TrimPrefix(declared, WorkspacePrefix)
	default:
		return "", false
	}
	if base == "" || !filepath.IsAbs(base) || rest == "" {
		return "", false
	}
	p := filepath.Join(base, rest)
	if !strings.HasPrefix(p, filepath.Clean(base)+"/") {
		return "", false
	}
	return p, true
}

// leaf is one key path of a JSON summary: a single value's hash, or the set
// of a list's entry hashes.
type leaf struct {
	key     []string
	list    bool
	hash    string
	entries map[string]bool
}

// Summary is one end of a file: its state and, for a JSON file, its leaves.
// It lives in memory only; the capture records the state and the changes.
type Summary struct {
	State  models.SensitiveState
	leaves map[string]leaf
}

// hasher hashes under the capture's key.
type hasher []byte

func (h hasher) sum(data []byte) string {
	m := hmac.New(sha256.New, h)
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

// Read summarises the file at path. owner is the uid the file must belong
// to, or negative for any; a file of another user is not read (the recorder
// is root, and a declared path that leads elsewhere, through a symbolic link
// say, must not make it read a file the agent's user cannot). The file is
// opened without blocking, so a FIFO at the path cannot stall the recorder.
func Read(path string, owner int, key []byte) Summary {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Summary{State: models.SensitiveState{State: models.SensitiveMissing}}
		}
		return Summary{State: models.SensitiveState{State: models.SensitiveUnreadable, Error: errText(err)}}
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return Summary{State: models.SensitiveState{State: models.SensitiveUnreadable, Error: errText(err)}}
	}
	if !fi.Mode().IsRegular() {
		return Summary{State: models.SensitiveState{State: models.SensitiveNotRegular}}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && owner >= 0 && int(st.Uid) != owner {
		return Summary{State: models.SensitiveState{State: models.SensitiveForeign}}
	}
	if fi.Size() > MaxBytes {
		return Summary{State: models.SensitiveState{State: models.SensitiveTooLarge}}
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return Summary{State: models.SensitiveState{State: models.SensitiveUnreadable, Error: errText(err)}}
	}
	if len(data) > MaxBytes {
		return Summary{State: models.SensitiveState{State: models.SensitiveTooLarge}}
	}
	return Summarize(data, key)
}

// errText is an error without the path, which the snapshot records apart.
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}

// Summarize summarises the bytes of a present file.
func Summarize(data []byte, key []byte) Summary {
	h := hasher(key)
	s := Summary{State: models.SensitiveState{State: models.SensitivePresent, Format: models.SensitiveOther, Digest: h.sum(data)}}
	v, ok := parseJSON(data)
	if !ok {
		return s
	}
	s.State.Format = models.SensitiveJSON
	s.leaves = map[string]leaf{}
	flatten(v, nil, h, s.leaves)
	return s
}

// parseJSON reads exactly one JSON value, keeping numbers as written.
func parseJSON(data []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}

// canonical is a value as compact JSON with object keys sorted, so equal
// values hash equal however the file spelled them.
func canonical(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// A decoded JSON value always marshals; keep the type visible.
		return []byte(fmt.Sprintf("%T", v))
	}
	return b
}

// pathKey is a key path as a map key: its JSON form, which no two paths
// share.
func pathKey(path []string) string {
	b, _ := json.Marshal(path)
	return string(b)
}

// flatten adds a leaf per key path under v. An object with keys is
// descended; an empty object is a value; a list is a set of entry hashes,
// each entry hashed whole.
func flatten(v any, path []string, h hasher, out map[string]leaf) {
	p := append([]string(nil), path...)
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 0 {
			out[pathKey(p)] = leaf{key: p, hash: h.sum(canonical(x))}
			return
		}
		for k, child := range x {
			flatten(child, append(p, k), h, out)
		}
	case []any:
		set := make(map[string]bool, len(x))
		for _, e := range x {
			set[h.sum(canonical(e))] = true
		}
		out[pathKey(p)] = leaf{key: p, list: true, entries: set}
	default:
		out[pathKey(p)] = leaf{key: p, hash: h.sum(canonical(x))}
	}
}

// Diff is what changed between two summaries of one file, taken under the
// same key. A deleted file is one change, with no key paths, so the
// capture does not list the keys of a file that is gone; a created JSON
// file lists its key paths as added.
func Diff(start, stop Summary) []models.SensitiveChange {
	a, b := start.State, stop.State
	if !a.Measured() || !b.Measured() {
		if a.State != b.State {
			return []models.SensitiveChange{{Kind: models.SensitiveUnmeasured}}
		}
		return nil
	}
	switch {
	case a.State == models.SensitiveMissing && b.State == models.SensitiveMissing:
		return nil
	case a.State == models.SensitiveMissing:
		out := []models.SensitiveChange{{Kind: models.SensitiveCreated}}
		if b.Format == models.SensitiveJSON {
			out = append(out, keyDiff(nil, stop.leaves)...)
		}
		return out
	case b.State == models.SensitiveMissing:
		return []models.SensitiveChange{{Kind: models.SensitiveDeleted}}
	case a.Digest == b.Digest:
		return nil
	case a.Format == models.SensitiveJSON && b.Format == models.SensitiveJSON:
		return keyDiff(start.leaves, stop.leaves)
	default:
		return []models.SensitiveChange{{Kind: models.SensitiveContent}}
	}
}

// keyDiff compares two JSON summaries key path by key path.
func keyDiff(a, b map[string]leaf) []models.SensitiveChange {
	keys := make([]string, 0, len(a)+len(b))
	paths := map[string][]string{}
	for k, l := range a {
		keys = append(keys, k)
		paths[k] = l.key
	}
	for k, l := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
			paths[k] = l.key
		}
	}
	// Key paths in order, element by element, so a key comes before the
	// keys beneath it.
	sort.Slice(keys, func(i, j int) bool { return lessPath(paths[keys[i]], paths[keys[j]]) })
	var out []models.SensitiveChange
	for _, k := range keys {
		la, inA := a[k]
		lb, inB := b[k]
		switch {
		case !inA:
			out = append(out, models.SensitiveChange{Key: lb.key, Kind: models.SensitiveAdded})
			if lb.list && len(lb.entries) > 0 {
				out = append(out, models.SensitiveChange{Key: lb.key, Kind: models.SensitiveEntriesAdded, Entries: len(lb.entries)})
			}
		case !inB:
			out = append(out, models.SensitiveChange{Key: la.key, Kind: models.SensitiveRemoved})
		case la.list != lb.list:
			out = append(out, models.SensitiveChange{Key: la.key, Kind: models.SensitiveChanged})
		case !la.list:
			if la.hash != lb.hash {
				out = append(out, models.SensitiveChange{Key: la.key, Kind: models.SensitiveChanged})
			}
		default:
			if n := missingFrom(lb.entries, la.entries); n > 0 {
				out = append(out, models.SensitiveChange{Key: la.key, Kind: models.SensitiveEntriesAdded, Entries: n})
			}
			if n := missingFrom(la.entries, lb.entries); n > 0 {
				out = append(out, models.SensitiveChange{Key: la.key, Kind: models.SensitiveEntriesRemoved, Entries: n})
			}
		}
	}
	return out
}

func lessPath(x, y []string) bool {
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

// missingFrom counts the entries of x that y lacks.
func missingFrom(x, y map[string]bool) int {
	n := 0
	for e := range x {
		if !y[e] {
			n++
		}
	}
	return n
}

// Snapshot is a capture's snapshot in progress: the Start summaries held in
// memory until Stop.
type Snapshot struct {
	key   []byte
	home  string
	owner int
	files []pending
}

type pending struct {
	declared, path string
	start          Summary
}

// Start reads every declared file that resolves, under a fresh random key.
// owner is the uid the files must belong to (negative for any). A
// declaration that does not resolve is left out; the verifier reports a
// declared file the snapshot does not name.
func Start(declared []string, home, workspace string, owner int) (*Snapshot, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("draw the snapshot key: %w", err)
	}
	return start(declared, home, workspace, owner, key), nil
}

func start(declared []string, home, workspace string, owner int, key []byte) *Snapshot {
	s := &Snapshot{key: key, home: home, owner: owner}
	seen := map[string]bool{}
	for _, d := range declared {
		if seen[d] {
			continue
		}
		seen[d] = true
		p, ok := Resolve(d, home, workspace)
		if !ok {
			continue
		}
		s.files = append(s.files, pending{declared: d, path: p, start: Read(p, owner, key)})
	}
	return s
}

// Stop reads every file again and returns the record: each end's state and
// the changes between them. The key is dropped with the snapshot.
func (s *Snapshot) Stop() models.SensitiveSnapshot {
	rec := models.SensitiveSnapshot{Home: s.home, Files: []models.SensitiveFile{}}
	for _, f := range s.files {
		stop := Read(f.path, s.owner, s.key)
		rec.Files = append(rec.Files, models.SensitiveFile{
			Declared: f.declared,
			Path:     f.path,
			Start:    f.start.State,
			Stop:     stop.State,
			Changes:  Diff(f.start, stop),
		})
	}
	return rec
}

// Changed counts the files with a change and the changes.
func Changed(rec models.SensitiveSnapshot) (files, changes int) {
	for _, f := range rec.Files {
		if len(f.Changes) > 0 {
			files++
			changes += len(f.Changes)
		}
	}
	return files, changes
}

// FormatKey writes a key path for a reader: identifier-like keys joined by
// dots, any other key quoted in brackets, and "(file)" for the empty path.
func FormatKey(key []string) string {
	if len(key) == 0 {
		return "(file)"
	}
	var b strings.Builder
	for i, k := range key {
		if isIdent(k) {
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(k)
			continue
		}
		q, _ := json.Marshal(k)
		b.WriteByte('[')
		b.Write(q)
		b.WriteByte(']')
	}
	return b.String()
}

func isIdent(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_' || r == '-' || r == '$' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
