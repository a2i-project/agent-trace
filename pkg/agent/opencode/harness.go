package opencode

import (
	"path/filepath"
	"regexp"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// What OpenCode 1.19.5 does on its own, measured on the six runs of the
// first capture (2026-11-03, I-122) and, where marked, in the survey of
// 1.19.5 (I-112 to I-116). Every path is under the home of the user the
// harness runs as; homes are matched as I-30 matches Claude Code's.

const homeRE = `/(?:home/[^/]+|root)`

// homePattern is a home a capture may record.
var homePattern = regexp.MustCompile(`^` + homeRE + `$`)

// harnessOwned are OpenCode's own directories (XDG data, state and cache):
// ~/.local/share/opencode (the session database, its log, tool outputs,
// snapshot repositories), ~/.local/state/opencode (its locks) and
// ~/.cache/opencode (its ripgrep and model catalog), as the survey found
// them written. Not ~/.config/opencode, which holds the configuration
// (SensitiveFiles). It names where, not what, and explains nothing (V-24).
var harnessOwned = regexp.MustCompile(`^` + homeRE + `/(?:\.local/share/opencode|\.local/state/opencode|\.cache/opencode)(?:/|$)`)

func isHarnessOwned(path string) bool { return harnessOwned.MatchString(path) }

// IsHarnessOwned reports whether path is under the harness's own
// directories.
func (Adapter) IsHarnessOwned(path string) bool { return isHarnessOwned(path) }

// HarnessCommands declares none: in a workspace that is not a git
// repository, the harness ran no command of its own in any run (I-122).
// The snapshot repository's git commands of a git workspace are not
// declared yet (I-116; see the adapters' page, Known limits).
func (Adapter) HarnessCommands() []string { return nil }

// HarnessHosts declares none: the harness connected to the model server
// in every run, which the baseline explains, and to no other host (V-34).
func (Adapter) HarnessHosts() []string { return nil }

// bookkeepingVersions are the versions whose database was measured.
var bookkeepingVersions = map[string]bool{"1.19.5": true}

// database is the session database and its journal files: OpenCode keeps
// it in write-ahead-log mode, and its -wal and -shm are written,
// checkpointed and deleted at the last close, whose timing the controls
// need not all show. -journal is SQLite's rollback journal, written when
// the log is off.
const database = `\.local/share/opencode/opencode\.db(?:-wal|-shm|-journal)?`

// HarnessBookkeeping declares the writes, closes and deletes of the
// session database and its journal files by the harness, of the measured
// version (V-50, I-122). Not an open, another file or another version.
func (Adapter) HarnessBookkeeping(version, home string) func(models.GroundTruthEvent) bool {
	if !bookkeepingVersions[version] {
		return nil
	}
	h := homeRE
	if home != "" {
		if !homePattern.MatchString(home) {
			return nil
		}
		h = regexp.QuoteMeta(home)
	}
	files := regexp.MustCompile(`^` + h + `/` + database + `$`)
	return func(e models.GroundTruthEvent) bool {
		switch e.ActionType {
		case models.FileWrite, models.FileClose, models.FileDelete:
			return files.MatchString(e.Target)
		}
		return false
	}
}

// Trace declares the trace (I-116, V-59, I-122): the session database
// ~/.local/share/opencode/opencode.db (Main), which holds every session
// of the account and so the run's and its subagents', with its -wal and
// -journal. A change to them by anything but the harness is tampering;
// reading them is not. So, as for Codex's thread databases (I-106) and
// agy's (V-75), the -shm is not covered: every reader of a database in
// write-ahead-log mode writes its index there. The -wal and -journal are
// Transient: a stock SQLite client that reads the database while no other
// process holds it creates them and deletes them at its close (V-76). The
// trace is the same with and without the session's id, since the database
// is one file (SessionTrace).
func (Adapter) Trace(_, home string) *verification.TraceDecl {
	h := homeRE
	if home != "" {
		if home != filepath.Clean(home) || !homePattern.MatchString(home) {
			return nil
		}
		h = regexp.QuoteMeta(home)
	}
	db := `^` + h + `/\.local/share/opencode/opencode\.db`
	main := regexp.MustCompile(db + `$`)
	all := regexp.MustCompile(db + `(?:-wal|-journal)?$`)
	transient := regexp.MustCompile(db + `(?:-wal|-journal)$`)
	return &verification.TraceDecl{
		Covers:    all.MatchString,
		Main:      main.MatchString,
		Transient: transient.MatchString,
	}
}

// SessionTrace is Trace for a session whose id the capture recorded
// (I-110): the database is the session's trace whatever its id, so the
// declaration does not narrow; an id that is not a session id declares
// nothing, so Trace decides.
func (a Adapter) SessionTrace(workspace, home string, s agent.TraceSession) *verification.TraceDecl {
	if !sessionIDRE.MatchString(s.ID) {
		return nil
	}
	return a.Trace(workspace, home)
}

// SensitiveFiles are the files whose change would change what the harness
// lets the agent do in a later session, as the survey of 1.19.5 found it
// reading them (I-113, I-123): the global configuration files and
// instruction file, the project's configuration files and its .opencode
// configuration, and the instruction files the harness reads from the
// workspace. The capture's flags and moves keep them out of the run, but a
// change made by a run reaches the next session that reads them. Each is
// checked whole.
func (Adapter) SensitiveFiles() []string {
	return []string{
		"~/.config/opencode/opencode.json",
		"~/.config/opencode/opencode.jsonc",
		"~/.config/opencode/config.json",
		"~/.config/opencode/AGENTS.md",
		"{workspace}/opencode.json",
		"{workspace}/opencode.jsonc",
		"{workspace}/.opencode/opencode.json",
		"{workspace}/.opencode/opencode.jsonc",
		"{workspace}/AGENTS.md",
	}
}

var (
	_ agent.SessionTraceDeclarer = Adapter{}
	_ agent.SessionParser        = Adapter{}
	_ agent.HarnessBookkeeper    = Adapter{}
	_ agent.StreamNormalizer     = Adapter{}
	_ agent.SensitiveDeclarer    = Adapter{}
)
