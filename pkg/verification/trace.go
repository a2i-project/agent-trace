package verification

import (
	"fmt"
	"sort"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// TraceDecl is an adapter's declaration of where its harness keeps the
// session's own trace, as the capture names those paths (I-74): the files
// the trajectory is read from. An agent can delete or rewrite them, so a
// change by anything but the harness's own process is tampering (V-59).
type TraceDecl struct {
	// Covers reports whether an observed path is part of the session's
	// trace: one of its files, a directory that holds only trace files, or
	// a path beneath one.
	Covers func(path string) bool
	// Main reports whether an observed path is a main session file, the
	// kind of file a reader is given as the trajectory. Nil declares none,
	// and the content the reader read is then compared with nothing.
	Main func(path string) bool
	// Transient reports whether a covered path is a file a reader of the
	// trace may create empty and delete again: a SQLite database's -wal
	// and -journal, which a stock client creates when it opens a database
	// no other process holds open and deletes when it closes it (V-76).
	// Nil declares none.
	Transient func(path string) bool
}

// TraceState is what the reader of the trace found when it read it.
type TraceState string

// The states of a trace. The zero value is a trace read whole as far as
// the reader can tell.
const (
	TraceRead TraceState = ""
	// TraceMissing: the file the reader was given does not exist.
	TraceMissing TraceState = "missing"
	// TraceEmpty: the file exists and holds no byte.
	TraceEmpty TraceState = "empty"
	// TraceUnparsable: the adapter could not read the file at all.
	TraceUnparsable TraceState = "unparsable"
	// TraceDamaged: the adapter read the file, but some of its records did
	// not parse.
	TraceDamaged TraceState = "damaged"
	// TraceDiffers: the file is not the content the probe hashed at the
	// last write of the main session file (set by Verify, V-59).
	TraceDiffers TraceState = "differs"
)

func (s TraceState) String() string {
	if s == TraceRead {
		return "read"
	}
	return string(s)
}

// TraceInput is the trace as the verifier takes it: the adapter's
// declaration of its paths and what the reader found when it read it.
type TraceInput struct {
	// Decl is the adapter's declaration (I-74). Nil declares nothing, and
	// no event or claim is read as tampering.
	Decl *TraceDecl
	// State and Detail are what the reader found. A state other than
	// TraceRead makes the run unverifiable: the claims are not aligned.
	State  TraceState
	Detail string
	// ReadHash is "sha256:<hex>" of the main session file the reader read,
	// set when the reader asks for it to be compared with the last content
	// the probe hashed (V-59). Empty compares nothing.
	ReadHash string
}

// TraceTamper is one piece of evidence that the trace was tampered with
// (V-59): a write-class event on a declared trace path by a process other
// than the agent's own, or a write-class claim of a declared trace path.
type TraceTamper struct {
	// Event is the observed event, nil for a claim.
	Event *models.GroundTruthEvent `json:"event,omitempty"`
	// Claim is the claim, nil for an event.
	Claim *models.TrajectoryEntry `json:"claim,omitempty"`
	// Zone is where the event's process sits ("subtree" or "outside"),
	// "claim" for a claim.
	Zone string `json:"zone"`
	// Level is the event's process level, -1 outside the tree and for a
	// claim.
	Level int `json:"level"`
	// Command is the command line of the level-1 command whose subtree
	// holds the event, when it exec'd.
	Command string `json:"command,omitempty"`
}

// TraceFile is a declared main session file the capture observed: the
// number of events on it and the last write-class one.
type TraceFile struct {
	Path   string                   `json:"path"`
	Events int                      `json:"events"`
	Last   *models.GroundTruthEvent `json:"last_write,omitempty"`
}

// Deleted reports whether the file's last write-class event is a delete.
func (f TraceFile) Deleted() bool {
	return f.Last != nil && f.Last.ActionType == models.FileDelete
}

// TraceCheck is what the verifier made of the trace (V-59).
type TraceCheck struct {
	// Declared is true when the adapter declared the trace's paths.
	Declared bool `json:"declared"`
	// State and Detail are the reader's, or TraceDiffers when the content
	// comparison failed.
	State  TraceState `json:"state,omitempty"`
	Detail string     `json:"detail,omitempty"`
	// Files are the declared main session files the capture observed.
	Files []TraceFile `json:"files,omitempty"`
	// Compared is true when the content the reader read was compared with
	// the last content the probe hashed, and Note says why it was not when
	// a comparison was asked for.
	Compared bool   `json:"compared,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Unreadable reports whether the trace could not be verified: deleted,
// empty, unparsable, damaged or not what the probe saw last.
func (c TraceCheck) Unreadable() bool { return c.State != TraceRead }

// TraceDeletedOrDamaged is the part of the reason for an unreadable trace
// that no other reason contains.
const TraceDeletedOrDamaged = "the trace was deleted or damaged"

// reason is the reason an unreadable trace gives.
func (c TraceCheck) reason() string {
	r := fmt.Sprintf("cannot verify: %s (%s", TraceDeletedOrDamaged, c.State)
	if c.Detail != "" {
		r += ": " + c.Detail
	}
	r += ")"
	var deleted []string
	for _, f := range c.Files {
		if f.Deleted() {
			deleted = append(deleted, f.Path)
		}
	}
	if len(deleted) > 0 {
		r += "; the capture shows the last write of " + strings.Join(deleted, ", ") + " was its deletion"
	}
	return r
}

// checkTrace reads the trace input against the capture: which declared main
// session files it observed, with the last write-class event on each, and,
// when the reader asks, whether the content it read is the last content
// the probe hashed of one of them (V-59). Only a file whose last
// write-class event is an unambiguous close carrying a hash can be
// compared; the content read must equal one such hash.
func checkTrace(in TraceInput, ground models.GroundTruth) TraceCheck {
	c := TraceCheck{Declared: in.Decl != nil && in.Decl.Covers != nil, State: in.State, Detail: in.Detail}
	if in.Decl != nil && in.Decl.Main != nil {
		byPath := map[string]*TraceFile{}
		for i := range ground {
			e := &ground[i]
			if !isFileEvent(e.ActionType) || e.PathIsAmbiguous || !in.Decl.Main(e.Target) {
				continue
			}
			f := byPath[e.Target]
			if f == nil {
				f = &TraceFile{Path: e.Target}
				byPath[e.Target] = f
			}
			f.Events++
			if writeClass(e.ActionType) && (f.Last == nil || !e.Timestamp.Before(f.Last.Timestamp)) {
				f.Last = e
			}
		}
		for _, f := range byPath {
			c.Files = append(c.Files, *f)
		}
		sort.Slice(c.Files, func(i, j int) bool { return c.Files[i].Path < c.Files[j].Path })
	}
	if in.ReadHash == "" || c.Unreadable() {
		return c
	}
	var hashed []string
	for _, f := range c.Files {
		if f.Last != nil && f.Last.ActionType == models.FileClose && f.Last.OutputHash != nil {
			hashed = append(hashed, f.Path+" "+*f.Last.OutputHash)
			if *f.Last.OutputHash == in.ReadHash {
				c.Compared = true
				return c
			}
		}
	}
	if len(hashed) == 0 {
		c.Note = "not compared: no declared main session file's last write in the capture is a close the probe hashed"
		return c
	}
	c.Compared = true
	c.State = TraceDiffers
	c.Detail = fmt.Sprintf("the file read (%s) is not the content the probe hashed at the last write of the session file (%s)", in.ReadHash, strings.Join(hashed, "; "))
	return c
}

// traceTampering lists the evidence that the trace was tampered with
// (V-59): every write-class event (write, close, rename, delete) on a path
// the declaration covers by a process that is not the agent's own, a
// command's subtree at any level or a process outside the tree, and every
// write-class claim, harness-implied ones aside, of a path it covers. The
// harness's own appends to its trace are level-0 events and are never
// listed. An event with no pid is unplaced, which already blocks FAITHFUL,
// and is not listed. An ambiguous event names a directory, and is listed
// when the declaration covers that directory. An event that changed
// nothing (unchanged: a read's close, a transient file created and deleted
// empty) is not listed (V-75, V-76).
func traceTampering(decl *TraceDecl, ground models.GroundTruth, claims models.Trajectory, forest *Forest) []TraceTamper {
	if decl == nil || decl.Covers == nil {
		return nil
	}
	same := unchanged(decl, ground)
	var out []TraceTamper
	for i := range ground {
		e := ground[i]
		if !writeClass(e.ActionType) || !decl.Covers(e.Target) || same[i] {
			continue
		}
		a := forest.Attribute(e)
		switch a.Zone {
		case ZoneSubtree, ZoneOutside:
		default:
			continue
		}
		t := TraceTamper{Event: &e, Zone: a.Zone.String(), Level: a.Level}
		if a.Command != nil && a.Command.Exec != nil {
			t.Command = a.Command.Exec.Target
		}
		out = append(out, t)
	}
	for i := range claims {
		c := claims[i]
		if implied(c) || !writeClass(c.ActionType) || !decl.Covers(c.Target) {
			continue
		}
		out = append(out, TraceTamper{Claim: &c, Zone: "claim", Level: -1})
	}
	return out
}

// emptyContentHash is the input hash the probe gives the open that created
// a file during the capture (P-22).
const emptyContentHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// traceFile is what one process did to one covered path since its last
// open of it.
type traceFile struct {
	open   bool // opened, and not closed since
	wrote  bool // a write or rename by the process since that open
	create int  // the index of the create of a transient file, -1 for none
}

// unchanged returns the indices of the write-class events on covered paths
// that changed nothing, which are not tampering:
//
//   - a close by a process that has not written or renamed the path since
//     its last open of it (V-75). The probe reports a close of every file
//     opened for writing, and a stock SQLite client opens a database for
//     writing to read it. A close with no open of its process in the
//     capture is not one: what the process did before is unknown.
//   - the create, and the delete, of a transient file (V-76) by a process
//     that wrote nothing to it in between, when no other process wrote,
//     renamed or deleted it in between and the capture shows the file did
//     not exist before the create: the last write, rename or delete of the
//     path before it is a delete, or the process's open that follows the
//     create, as its next event on the path, carries the input hash of
//     empty content, which the probe gives only the open that created a
//     file. The create is a file_write that may as well be a truncation,
//     so without that evidence both stay tampering.
//
// A process's events are its pid's, and a fork of the pid starts afresh.
// Ambiguous events name a directory and are never unchanged.
func unchanged(decl *TraceDecl, ground models.GroundTruth) map[int]bool {
	type key struct {
		pid  uint32
		path string
	}
	files := map[key]*traceFile{}
	last := map[key]int{} // index of the process's last event on the path
	// The index of the last write, rename or delete of each path, and the
	// kind of the one before it.
	lastChange, priorChange := map[string]int{}, map[string]models.ActionType{}
	same := map[int]bool{}
	transient := func(p string) bool { return decl.Transient != nil && decl.Transient(p) }
	for i, e := range ground {
		if e.ActionType == models.ProcessFork {
			for k := range files {
				if k.pid == e.PID {
					delete(files, k)
					delete(last, k)
				}
			}
			continue
		}
		if !isFileEvent(e.ActionType) || e.PathIsAmbiguous || e.PID == 0 || !decl.Covers(e.Target) {
			continue
		}
		k := key{e.PID, e.Target}
		f := files[k]
		prev, seen := last[k]
		last[k] = i
		switch e.ActionType {
		case models.FileOpen:
			create := -1
			if f != nil {
				create = f.create
			}
			if create < 0 && transient(e.Target) && seen && ground[prev].ActionType == models.FileWrite &&
				(emptyAtOpen(e) || (lastChange[e.Target] == prev && priorChange[e.Target] == models.FileDelete)) {
				create = prev
			}
			files[k] = &traceFile{open: true, create: create}
		case models.FileClose:
			if f != nil && f.open && !f.wrote {
				same[i] = true
			}
			if f != nil {
				f.open = false
			}
		case models.FileWrite, models.FileRename, models.FileDelete:
			if e.ActionType == models.FileDelete && f != nil && f.create >= 0 && !f.wrote {
				same[f.create], same[i] = true, true
			}
			if f != nil {
				f.wrote, f.create = true, -1
			}
			// Another process's change ends every transient window on
			// the path.
			for o, g := range files {
				if o.path == e.Target && o.pid != e.PID {
					g.create = -1
				}
			}
			if j, ok := lastChange[e.Target]; ok {
				priorChange[e.Target] = ground[j].ActionType
			}
			lastChange[e.Target] = i
		}
	}
	return same
}

// emptyAtOpen reports whether an open carries the input hash of empty
// content, which the probe gives only the open that created a file (P-22).
func emptyAtOpen(o models.GroundTruthEvent) bool {
	return o.InputHash != nil && *o.InputHash == emptyContentHash
}

func isFileEvent(t models.ActionType) bool {
	return LaneOf(t) == LaneFS
}
