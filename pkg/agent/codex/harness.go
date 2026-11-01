package codex

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// What Codex 0.166.0 does on its own, measured on the six runs of the first
// capture (2026-11-01, I-83). Every path is under the home of the user the
// harness runs as; homes are matched as I-30 matches Claude Code's.

const homeRE = `/(?:home/[^/]+|root)`

// homePattern is a home a capture may record.
var homePattern = regexp.MustCompile(`^` + homeRE + `$`)

// harnessOwned is Codex's own directory, ~/.codex: its sessions, shell
// snapshots, databases, caches, the arg0 directory of its helper links and
// its thread locks. An unexplained level-0 file event there is unexplained
// harness activity (V-24). It names where, not what, and explains nothing.
var harnessOwned = regexp.MustCompile(`^` + homeRE + `/\.codex(?:/|$)`)

// IsHarnessOwned reports whether path is under the harness's own directory.
func (Adapter) IsHarnessOwned(path string) bool { return harnessOwned.MatchString(path) }

// launcherScript is the npm package's entry point, which the root of every
// run of the capture opened before it started the native binary, and
// nativeHarness the native binary's exec of codex exec.
var (
	launcherScript = regexp.MustCompile(`^/\S*/node_modules/@openai/codex/bin/codex\.js$`)
	nativeHarness  = regexp.MustCompile(`^/\S*/node_modules/@openai/codex-linux-[0-9a-z_]+/vendor/[^/ ]+/bin/codex exec(?: |$)`)
)

// HarnessProcess names the native harness when the capture's root is the
// npm launcher (I-81, I-82): the root opened the package's bin/codex.js and
// a child of it exec'd the vendored binary with exec. agent.Rooted checks
// that the root did nothing else.
func (Adapter) HarnessProcess(g models.GroundTruthFile) uint32 {
	script := false
	var pid uint32
	for _, e := range g.Events {
		switch {
		case e.PID == g.RootPID && e.ActionType == models.FileOpen && launcherScript.MatchString(e.Target):
			script = true
		case e.ActionType == models.ProcessExec && e.PPID == g.RootPID && e.PID != g.RootPID &&
			!e.TargetTruncated && nativeHarness.MatchString(e.Target):
			if pid != 0 && pid != e.PID {
				return 0
			}
			pid = e.PID
		}
	}
	if !script {
		return 0
	}
	return pid
}

// gitRemote is the one command the harness started in some runs and not
// others: at the end of the task run, after the turn's last item, and in no
// control. In the survey of 0.166.0 it followed every turn that applied a
// patch (I-83).
const gitRemote = "/usr/bin/git -c safe.bareRepository=explicit -c core.hooksPath=/dev/null -c core.fsmonitor=false remote -v"

// HarnessCommands declares the harness's occasional command (V-43). Its exec
// is the one that took effect: NormalizeStream drops the failed attempts of
// the PATH search before it, which name the harness's per-run arg0
// directory (failedAttempts).
func (Adapter) HarnessCommands() []string { return []string{gitRemote} }

// HarnessHosts declares none: the capture's harness connected to chatgpt.com
// and ab.chatgpt.com in every run, which the baseline explains, and to no
// other host (V-34).
func (Adapter) HarnessHosts() []string { return nil }

// housekeepingVersions are the versions whose model traffic is declared.
var housekeepingVersions = map[string]bool{"0.166.0": true}

// modelAPI is the endpoint Codex 0.166.0 talks to its model through: a
// WebSocket opened by a GET upgrade, over which each request is one client
// message. With content capture the net probe writes the upgrade as a
// net_request of GET and each client message as a net_request of method WS
// with the hash of the message.
const modelAPI = "https://chatgpt.com/backend-api/codex/responses"

// HarnessHousekeeping declares the harness's model traffic, of the
// declared version (V-54, I-89): the upgrade GET of the model endpoint
// without a body, and every client message on that WebSocket, with a body.
// The exact host and path only; another path or host, a GET with a body
// and a message without one stay checked, and the verifier applies the
// declaration to level-0 events, the harness process's own.
func (Adapter) HarnessHousekeeping(version string) []agent.Housekeeping {
	if !housekeepingVersions[version] {
		return nil
	}
	return []agent.Housekeeping{
		{ActionType: models.NetRequest, Target: "GET " + modelAPI},
		{ActionType: models.NetRequest, Target: "WS " + modelAPI, Body: true},
	}
}

// bookkeepingVersions are the versions whose databases were measured.
var bookkeepingVersions = map[string]bool{"0.166.0": true}

// databases are the harness's SQLite databases under ~/.codex, each kept in
// write-ahead-log mode: their -wal and -shm files are written, checkpointed
// into the database and deleted at the last close, and which of these a run
// shows varies with when the checkpoint falls (between one and five of the
// six runs for each file).
const databases = `(?:state_5|thread_history_1|logs_2|goals_1|queue_1|memories_1)\.sqlite(?:-wal|-shm)?`

// maintenanceLock is the lock of the harness's SQLite maintenance (I-95):
// the strings of the 0.166.0 binary name it beside the logs database's
// checkpoint and pruning statements. On the codex-parity-1 long run the
// harness process opened it once, 60 s after it started, just before it
// opened logs_2.sqlite, and closed it empty at its exit; no control, each
// shorter than a minute, touched it.
const maintenanceLock = `\.sqlite-maintenance\.lock`

// HarnessBookkeeping declares the writes, closes and deletes of the
// harness's databases under ~/.codex, and the open and close of its
// maintenance lock, of the measured version (V-50, I-95). Not an open of a
// database, a write of the lock, another file or another version.
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
	files := regexp.MustCompile(`^` + h + `/\.codex/` + databases + `$`)
	lock := regexp.MustCompile(`^` + h + `/\.codex/` + maintenanceLock + `$`)
	return func(e models.GroundTruthEvent) bool {
		switch e.ActionType {
		case models.FileWrite, models.FileDelete:
			return files.MatchString(e.Target)
		case models.FileClose:
			return files.MatchString(e.Target) || lock.MatchString(e.Target)
		case models.FileOpen:
			return lock.MatchString(e.Target)
		}
		return false
	}
}

// Trace declares the session's own trace (I-84), as the user chose it: every
// rollout under ~/.codex/sessions (Main; the session's subagents keep
// rollouts of their own there, and a rollout's name does not hold the
// workspace), and the two databases that keep the account's threads,
// ~/.codex/thread_history_1.sqlite and ~/.codex/state_5.sqlite, with their
// write-ahead log and shared memory. The home is the capture's, else any
// home I-30 declares.
func (Adapter) Trace(_, home string) *verification.TraceDecl {
	h := homeRE
	if home != "" {
		if home != filepath.Clean(home) || !homePattern.MatchString(home) {
			return nil
		}
		h = regexp.QuoteMeta(home)
	}
	main := regexp.MustCompile(`^` + h + `/\.codex/sessions/[0-9]{4}/[0-9]{2}/[0-9]{2}/rollout-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}-` + uuidRE + `\.jsonl$`)
	dbs := regexp.MustCompile(`^` + h + `/\.codex/(?:thread_history_1|state_5)\.sqlite(?:-wal|-shm|-journal)?$`)
	return &verification.TraceDecl{
		Covers: func(p string) bool { return main.MatchString(p) || dbs.MatchString(p) },
		Main:   main.MatchString,
	}
}

// SensitiveFiles are the files whose change would change what the harness
// lets the agent do, as the strings of the 0.166.0 binary name them (I-85):
// the user's configuration and its managed and required layers, the hooks
// file, and the project's configuration. The capture's invocation passes
// --ignore-user-config, but a change made by a run reaches the next session
// that does not.
func (Adapter) SensitiveFiles() []string {
	return []string{
		"~/.codex/config.toml",
		"~/.codex/managed_config.toml",
		"~/.codex/requirements.toml",
		"~/.codex/hooks.json",
		"{workspace}/.codex/config.toml",
	}
}

const uuidRE = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

// The per-run ids in the harness's own paths and commands (I-83), each
// replaced by a fixed token where runs are compared.
var canonicalIDs = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`(/\.codex/sessions/)[0-9]{4}/[0-9]{2}/[0-9]{2}/rollout-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}-` + uuidRE + `\.jsonl`), "${1}{date}/rollout-{time}-{id}.jsonl"},
	{regexp.MustCompile(`(/\.codex/shell_snapshots/)` + uuidRE + `\.tmp-[0-9]+`), "${1}{id}.tmp-{n}"},
	{regexp.MustCompile(`(/\.codex/shell_snapshots/)` + uuidRE + `\.[0-9]+\.sh`), "${1}{id}.{n}.sh"},
	{regexp.MustCompile(`(/\.codex/tmp/arg0-linux/codex-arg0)[0-9A-Za-z]{6}`), "${1}{id}"},
	{regexp.MustCompile(`(/\.codex/thread-writer-locks/)` + uuidRE + `\.lock`), "${1}{id}.lock"},
	{regexp.MustCompile(`(/\.codex/cache/codex_apps_[a-z_]+/)\.tmp[0-9A-Za-z]{6}`), "${1}.tmp{id}"},
}

func canonicalTarget(t string) string {
	if !strings.Contains(t, "/.codex/") {
		return t
	}
	for _, c := range canonicalIDs {
		t = c.re.ReplaceAllString(t, c.with)
	}
	return t
}

var _ agent.Launcher = Adapter{}
