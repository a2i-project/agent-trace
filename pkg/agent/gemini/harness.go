package gemini

import (
	"regexp"
	"strings"
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

var (
	uuidRE        = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	crashRE       = regexp.MustCompile(`/crashes/crash_\d+_`)
	stepRE        = regexp.MustCompile(`/\.system_generated/steps/\d+/`)
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
// the step index of a step's output file and
// the chunk index of a transcript chunk, the random suffix of the embedded
// ripgrep's temporary and of the auto-updater's write test, and the number of
// the pseudo-terminal a command runs on. Any other path is returned as it is.
func canonicalPath(p string) string {
	switch {
	case harnessAppDir.MatchString(p):
		p = uuidRE.ReplaceAllString(p, "{id}")
		p = crashRE.ReplaceAllString(p, "/crashes/crash_{pid}_")
		p = stepRE.ReplaceAllString(p, "/.system_generated/steps/{n}/")
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
