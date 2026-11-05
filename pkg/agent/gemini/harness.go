package gemini

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// What the harness does around the agent's calls, measured on agy 1.3.4 with
// strace -f of three print-mode runs on 2026-10-13 (I-47, I-48 in
// docs/decisions/integration.md).
//
// A run_command call is executed as a child of the agy process that runs
//
//	bash -c <CommandLine>
//
// with the call's Cwd as its working directory and a fresh pseudo-terminal
// as its standard streams. The process probe records the executed path and
// argv[1:], so the observed target is "/usr/bin/bash -c <CommandLine>" (the
// path is the one the harness found on PATH). There is nothing around the
// command: no snapshot, no eval, no suffix.

// shellPrefixes are the wrapper as the process probe records it. Only bash
// was seen; /bin/bash is the same file on a merged-/usr system, and which of
// the two the harness execs depends on the order of PATH.
var shellPrefixes = []string{"/usr/bin/bash -c ", "/bin/bash -c "}

// commandOf recovers the CommandLine of a run_command from an observed
// process target. ok is false when the target is not the wrapper, in which
// case the caller keeps the target: a program the harness ran some other way
// shows as itself, never as a guessed command (D6).
//
// The probe joins argv with spaces, so `bash -c 'echo' 'hi'` (which runs
// echo with $0 set to hi) and `bash -c 'echo hi'` record the same target and
// recover the same command. What the shell then ran is its subtree, which
// the claim explains either way; the difference is $0 only.
func commandOf(target string) (string, bool) {
	for _, p := range shellPrefixes {
		if strings.HasPrefix(target, p) && len(target) > len(p) {
			return target[len(p):], true
		}
	}
	return "", false
}

// harnessOwned matches where agy keeps its own files, as far as the strace of
// one print-mode run showed them on 2026-10-13: its application directory
// (conversation databases, the per-conversation brain directory with its
// transcripts and step outputs, caches, annotations, presence locks, crash
// logs, its summaries and the agentapi shim it rewrites before every
// command), the cache directory it extracts its embedded ripgrep into, the
// auto-updater's write test in the directory that holds the binary, and its
// feature-flag cache in /tmp. The install directory itself is not declared:
// a write to the binary is a finding. Neither is the workspace's .agents
// directory, which belongs to the project.
var harnessOwned = regexp.MustCompile(`^(?:/(?:home/[^/]+|root)/(?:\.gemini/antigravity-cli(?:/|$)|\.cache/antigravity(?:/|$)|\.local/bin/\.update_test\d+$)|/tmp/unleash-repo-schema-v1-codeium-language-server\.json$)`)

// IsHarnessOwned reports whether path is one of the harness's own files or
// directories (V-24, I-48).
func (Adapter) IsHarnessOwned(path string) bool { return harnessOwned.MatchString(path) }

// HarnessHosts are agy's own service hosts that it connects to only sometimes
// (V-34, I-52). oauth2.googleapis.com is its access-token refresh: on the
// paired capture of agy 1.3.4 (2026-10-13) the agent's own process connected
// to it once, one second into the task run, and in none of the five controls.
// Every other host its process named there (daily-cloudcode-pa.googleapis.com,
// antigravity-unleash.goog, play.googleapis.com, www.googleapis.com,
// lh3.googleusercontent.com) was in all six runs, so the baseline explains
// it and it is not declared.
func (Adapter) HarnessHosts() []string { return []string{"oauth2.googleapis.com"} }

// housekeepingVersions are the versions whose token renewal is declared:
// 1.4.7, whose content capture shows the renewal's request and whose binary
// holds its URL. 1.3.4 renewed on both of its paired captures, but without
// request content, so only its connection is measured; it declares nothing
// and the connection stays unexplained harness network activity (V-34).
var housekeepingVersions = map[string]bool{"1.4.7": true}

// tokenRenewal is agy's renewal of its access token (V-85): on the content
// capture of the basic task with agy 1.4.7 (2026-11-03) the agent's own
// process, at the start of the task run and in none of the five controls,
// connected to oauth2.googleapis.com and POSTed a body to its token
// endpoint, https://oauth2.googleapis.com/token, with no query, which the
// strings of the binary hold (**Reported**). Its GET of the account's
// userinfo on www.googleapis.com, which every run makes, the baseline
// explains, so it is not declared.
var tokenRenewal = []agent.Housekeeping{
	{ActionType: models.NetConnect, Target: "oauth2.googleapis.com"},
	{ActionType: models.NetRequest, Target: "POST https://oauth2.googleapis.com/token", Body: true},
}

// flagMetrics is the feature-flag client's usage report (V-93): on every
// run of agy 1.4.7 that lasted a minute (the search and long parity runs and
// the three long controls that did, 2026-11-05) the agent's own process
// POSTed a body to https://antigravity-unleash.goog/api/client/metrics
// exactly once, 60 s after its start, on the connection to the flag server
// that every run opens, and no shorter run sent it. The flag fetches of the
// same interval (GETs of /api/client/features) the baseline explains, as
// every run makes one at its start.
var flagMetrics = agent.Housekeeping{ActionType: models.NetRequest, Target: "POST https://antigravity-unleash.goog/api/client/metrics", Body: true}

// metricsVersions are the versions whose flag metrics are declared.
var metricsVersions = map[string]bool{"1.4.7": true}

// bookkeepingVersions are the versions whose background-task bookkeeping is
// declared (V-92).
var bookkeepingVersions = map[string]bool{"1.4.7": true}

// HarnessBookkeeping declares the files agy 1.4.7 keeps for a command it
// moved to the background (V-92), measured on the long parity run
// (2026-11-05), where seven run_command calls outlived their wait and became
// tasks: under the conversation's brain directory,
// <home>/.gemini/antigravity-cli/brain/<id>/.system_generated/, the task's
// output log tasks/task-<step>.log (opened, written and closed while the
// command runs, and opened by a manage_task status call), and the notice of
// the task's end it leaves for the conversation in messages/: the temporary
// .<id>.<id>.tmp written and renamed onto <id>.json, which the harness then
// opens, the marker undelivered/<id> written and deleted, and read.json. No
// control starts a background task, so no baseline holds them. Not a
// create, another file under the directory, or another version.
func (Adapter) HarnessBookkeeping(version, home string) func(models.GroundTruthEvent) bool {
	f, ok := taskFiles(version, home)
	if !ok {
		return nil
	}
	return func(e models.GroundTruthEvent) bool {
		t := e.Target
		switch e.ActionType {
		case models.FileOpen:
			return f.log.MatchString(t) || f.temp.MatchString(t) || f.notice.MatchString(t) || f.read.MatchString(t) || f.marker.MatchString(t)
		case models.FileWrite, models.FileClose:
			return f.log.MatchString(t) || f.temp.MatchString(t) || f.read.MatchString(t) || f.marker.MatchString(t)
		case models.FileRename:
			return f.temp.MatchString(t) || f.notice.MatchString(t)
		case models.FileDelete:
			return f.marker.MatchString(t)
		}
		return false
	}
}

// HarnessClaimedWrites names the task logs of HarnessBookkeeping, the one
// file of V-92 the agent reads while the harness writes it (V-94): on the
// long parity run of 1.4.7 the agent read a running task's log with
// view_file, and the agent's own process kept appending the command's
// output to it, an open, a write and a close about once a second, 32 times.
// On a log that claims name only as opened, those writes and their opens
// stay explained and the agent's read stays checked. No other file of V-92
// is declared: no call of the agent names one.
func (Adapter) HarnessClaimedWrites(version, home string) func(string) bool {
	f, ok := taskFiles(version, home)
	if !ok {
		return nil
	}
	return f.log.MatchString
}

// backgroundFiles are the patterns of the files of V-92.
type backgroundFiles struct{ log, temp, notice, read, marker *regexp.Regexp }

// taskFiles builds backgroundFiles for a version in bookkeepingVersions and
// the capture's home (any home I-30 declares when it is empty); ok is false
// for another version or a home that is not a clean /home/<user> or /root.
func taskFiles(version, home string) (backgroundFiles, bool) {
	if !bookkeepingVersions[version] {
		return backgroundFiles{}, false
	}
	h := homeRE
	if home != "" {
		if home != filepath.Clean(home) || !homePattern.MatchString(home) {
			return backgroundFiles{}, false
		}
		h = regexp.QuoteMeta(home)
	}
	const id = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
	dir := `^` + h + `/\.gemini/antigravity-cli/brain/` + id + `/\.system_generated/`
	return backgroundFiles{
		log:    regexp.MustCompile(dir + taskLogTail),
		temp:   regexp.MustCompile(dir + `messages/\.` + id + `\.` + id + `\.tmp$`),
		notice: regexp.MustCompile(dir + `messages/` + id + `\.json$`),
		read:   regexp.MustCompile(dir + `messages/read\.json$`),
		marker: regexp.MustCompile(dir + `messages/undelivered/` + id + `$`),
	}, true
}

// taskLogTail is a background task's log below a conversation's
// .system_generated directory.
const taskLogTail = `tasks/task-\d+\.log$`

// HarnessHousekeeping declares the token renewal of the versions in
// housekeepingVersions and the flag metrics of those in metricsVersions as
// the harness's own network housekeeping (V-54, V-85, V-93). An agy session states no version, so the version is the one the
// capture recorded (agent.DeclarationVersion). The exact host and path
// only: another path, a query, another method or a POST without a body on
// that host stays checked, and a claim naming the host keeps its events in
// the alignment (V-54).
func (Adapter) HarnessHousekeeping(version string) []agent.Housekeeping {
	var hk []agent.Housekeeping
	if housekeepingVersions[version] {
		hk = append(hk, tokenRenewal...)
	}
	if metricsVersions[version] {
		hk = append(hk, flagMetrics)
	}
	return hk
}

// SensitiveFiles are agy's security-sensitive files (V-40, I-59), the three
// configuration files its process opened at start-up in every run of the
// paired captures of agy 1.3.4 (2026-10-13 and 2026-10-17) and that its
// binary names as where it persists settings: the CLI settings
// ~/.gemini/antigravity-cli/settings.json (its permission allow-list,
// trusted workspaces and MCP servers; "Persist to settings.json" is what an
// always-allow answer does), the shared configuration
// ~/.gemini/config/config.json (installed plugins) and the MCP servers
// ~/.gemini/config/mcp_config.json. No capture shows agy writing any of
// them at rest. The administrator's /etc/antigravity/admin_settings.json is
// not declared: it is root's, outside the agent's user's home.
func (Adapter) SensitiveFiles() []string {
	return []string{
		"~/.gemini/antigravity-cli/settings.json",
		"~/.gemini/config/config.json",
		"~/.gemini/config/mcp_config.json",
	}
}

var (
	uuidRE        = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	crashRE       = regexp.MustCompile(`/crashes/crash_\d+_`)
	stepRE        = regexp.MustCompile(`/\.system_generated/steps/\d+(/|$)`)
	logRE         = regexp.MustCompile(`/log/cli-\d{8}_\d{6}\.log$`)
	chunkRE       = regexp.MustCompile(`/\.system_generated/logs/chunks/(transcript(?:_full)?)/\d+\.jsonl$`)
	rgTempRE      = regexp.MustCompile(`/\.cache/antigravity/bin/\.rg_embedded-\d+$`)
	updateTestRE  = regexp.MustCompile(`^(/(?:home/[^/]+|root)/\.local/bin/\.update_test)\d+$`)
	ptsRE         = regexp.MustCompile(`^/dev/pts/\d+$`)
	deletedSuffix = regexp.MustCompile(` \(deleted\)$`)
	harnessAppDir = regexp.MustCompile(`^/(?:home/[^/]+|root)/\.gemini/antigravity-cli/`)
)

// canonicalPath replaces the per-run ids in the harness's own file paths
// with fixed tokens (I-48): the conversation id and the other UUIDs the
// application directory names files by (temporaries are <name>.<uuid>.tmp),
// the pid in a crash log's name, the start time in the name of the run's log,
// the step index of a step's directory and of the files in it (I-49), the
// chunk index of a transcript chunk, the random suffix of the embedded
// ripgrep's temporary and of the auto-updater's write test, and the number of
// the pseudo-terminal a command runs on. Any other path is returned as it is.
func canonicalPath(p string) string {
	switch {
	case harnessAppDir.MatchString(p):
		p = uuidRE.ReplaceAllString(p, "{id}")
		p = crashRE.ReplaceAllString(p, "/crashes/crash_{pid}_")
		p = stepRE.ReplaceAllString(p, "/.system_generated/steps/{n}$1")
		p = chunkRE.ReplaceAllString(p, "/.system_generated/logs/chunks/$1/{n}.jsonl")
		p = logRE.ReplaceAllString(p, "/log/cli-{time}.log")
	case rgTempRE.MatchString(p):
		p = p[:strings.LastIndexByte(p, '-')+1] + "{n}"
	case updateTestRE.MatchString(p):
		p = updateTestRE.ReplaceAllString(p, "$1{n}")
	case ptsRE.MatchString(p):
		p = "/dev/pts/{n}"
	}
	return p
}
