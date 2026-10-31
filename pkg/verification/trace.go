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
// when the declaration covers that directory.
func traceTampering(decl *TraceDecl, ground models.GroundTruth, claims models.Trajectory, forest *Forest) []TraceTamper {
	if decl == nil || decl.Covers == nil {
		return nil
	}
	var out []TraceTamper
	for i := range ground {
		e := ground[i]
		if !writeClass(e.ActionType) || !decl.Covers(e.Target) {
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

func isFileEvent(t models.ActionType) bool {
	return LaneOf(t) == LaneFS
}
