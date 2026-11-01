package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// TraceDeclarer is implemented by an adapter that can name where its
// harness keeps the session's own trace, the files its Parse reads (I-74):
// Claude Code's transcript and its subagents' directory, Codex's rollout
// files, agy's conversation database. Given the capture's workspace and the
// home it resolved "~/" against (empty when the capture does not say), it
// returns the paths as the capture names them, or nil when it cannot name
// them. The verifier reads a write-class event on them by any process but
// the agent's own, and a write-class claim of them, as trace tampering, a
// finding (V-59). The declaration names where the trace is, never what the
// harness does there: the harness's own appends are the agent process's
// events and are never tampering.
type TraceDeclarer interface {
	Trace(workspace, home string) *verification.TraceDecl
}

// SessionTraceDeclarer is a TraceDeclarer whose trace is the files of one
// session, named by the session's id, which the session's own record states
// (Report.TraceSession): agy names a conversation's database by the
// conversation's id, and the account's other conversations are not the
// session's trace (I-105). Given the id, SessionTrace declares that
// session's files only; Trace declares what the adapter can name without
// it.
type SessionTraceDeclarer interface {
	TraceDeclarer
	SessionTrace(workspace, home, session string) *verification.TraceDecl
}

// Trace is the adapter's trace declaration for a capture, or nil. session
// is the id the session's record states (Report.TraceSession), empty when it
// states none.
func Trace(a Adapter, g models.GroundTruthFile, session string) *verification.TraceDecl {
	d, ok := a.(TraceDeclarer)
	if !ok {
		return nil
	}
	home := ""
	if g.Sensitive != nil {
		home = g.Sensitive.Home
	}
	if s, ok := a.(SessionTraceDeclarer); ok && session != "" {
		return s.SessionTrace(g.Workspace, home, session)
	}
	return d.Trace(g.Workspace, home)
}

// MangledWorkspace is the workspace as Claude Code names its per-project
// directory (I-70). ok is false for a name longer than the harness keeps
// as it is; the name returned is then the whole mangled form, of which the
// harness keeps the first 200 characters and appends a hash.
func MangledWorkspace(workspace string) (name string, ok bool) {
	return mangle(workspace)
}

// MaxMangled is the longest per-project directory name Claude Code keeps
// as it is (I-70).
const MaxMangled = maxMangled

// ReadTrace reads a session through the adapter as cmd/verify and
// cmd/analyze take it (V-59): a file that does not exist, holds no byte,
// that the adapter cannot read or of which some record does not parse is
// a trace that cannot be verified, returned as its state with the reason
// and no claims, never as an error. An error is returned only when the file
// exists and cannot be examined (a permission, an I/O error). With hash,
// the file's SHA-256 is returned in the input, for the verifier to compare
// with the last content the probe hashed. An adapter that declares no trace
// (TraceDeclarer) reads as before: its Parse error is returned and its
// parse errors stay in the report, since nothing says the file is the
// harness's own trace.
func ReadTrace(a Adapter, path string, hash bool) (models.Trajectory, Report, verification.TraceInput, error) {
	in := verification.TraceInput{}
	if _, ok := a.(TraceDeclarer); !ok {
		tr, rep, err := a.Parse(path)
		return tr, rep, in, err
	}
	st, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		in.State, in.Detail = verification.TraceMissing, path+" does not exist"
		return nil, Report{}, in, nil
	case err != nil:
		return nil, Report{}, in, err
	case st.Mode().IsRegular() && st.Size() == 0:
		in.State, in.Detail = verification.TraceEmpty, path+" holds no byte"
		return nil, Report{}, in, nil
	}
	tr, rep, err := a.Parse(path)
	if err != nil {
		in.State, in.Detail = verification.TraceUnparsable, fmt.Sprintf("the %s adapter cannot read %s: %v", a.Name(), path, err)
		return nil, rep, in, nil
	}
	if len(rep.ParseErrors) > 0 {
		in.State, in.Detail = verification.TraceDamaged, fmt.Sprintf("%d record(s) of %s did not parse, the first: %s", len(rep.ParseErrors), path, rep.ParseErrors[0])
		return tr, rep, in, nil
	}
	if hash && st.Mode().IsRegular() {
		h, err := content.SHA256File(path)
		if err != nil {
			return nil, Report{}, in, err
		}
		in.ReadHash = h
	}
	return tr, rep, in, nil
}
