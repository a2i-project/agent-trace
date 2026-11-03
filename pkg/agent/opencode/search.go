package opencode

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// A grep or glob call runs OpenCode's own ripgrep as a child of the
// harness (I-124). The survey of 1.19.5 (strace, 2026-11-03) saw
//
//	<home>/.cache/opencode/bin/rg --no-config --json --hidden --no-messages --glob=!**/.git/** -- <pattern> .
//	<home>/.cache/opencode/bin/rg --no-config --files --glob=<pattern> --glob=!**/.git/** .
//
// each with the searched folder as its working directory; the strings of
// the binary add a grep's --glob=<include> before the .git exclusion and a
// glob's --hidden and --follow after --files. The harness downloads that
// ripgrep once per home (I-112, I-116). A search is claimed and observed
// as its kind and its folder, as Claude Code's (I-108); its pattern is not
// verified.
const (
	// SearchGrep and SearchGlob are the claimed and normalized targets
	// of a grep and a glob call, each followed by the folder.
	SearchGrep = "opencode search:grep"
	SearchGlob = "opencode search:glob"
)

// ownRipgrep is OpenCode's own ripgrep, under the home of the user the
// harness runs as. An rg from PATH, or anywhere else, is not a search.
var ownRipgrep = regexp.MustCompile(`^(?:/home/[^/\s]+|/root)/\.cache/opencode/bin/rg$`)

const gitExclusion = "--glob=!**/.git/**"

// searchKind classifies the arguments after the program as a grep or a
// glob in the measured shapes, or neither. The harness's own listing (a
// glob with no pattern of its own) is neither.
func searchKind(rest string) (string, bool) {
	switch {
	case strings.HasPrefix(rest, "--no-config --json --hidden --no-messages ") &&
		strings.Contains(rest, " "+gitExclusion+" -- ") && strings.HasSuffix(rest, " ."):
		return SearchGrep, true
	case strings.HasPrefix(rest, "--no-config --files ") && strings.HasSuffix(rest, " "+gitExclusion+" .") &&
		strings.Contains(strings.TrimSuffix(rest, " "+gitExclusion+" ."), " --glob="):
		return SearchGlob, true
	}
	return "", false
}

// searchTarget is the normalized target of the exec of OpenCode's own
// ripgrep in a measured shape: its kind and its working directory. When
// the probe cut the command line after the shape's start, or did not
// record the working directory, the target is the kind alone, marked
// truncated: it pairs by prefix with a claim of that kind, unverified
// (V-26), never as a mismatch.
func searchTarget(e models.GroundTruthEvent) (string, bool, bool) {
	prog, rest, _ := strings.Cut(e.Target, " ")
	if !ownRipgrep.MatchString(prog) || (e.Image != nil && e.Image.Program != "" && e.Image.Program != prog) {
		return "", false, false
	}
	if e.TargetTruncated {
		for _, start := range []string{"--no-config --json --hidden --no-messages ", "--no-config --files "} {
			if strings.HasPrefix(rest, start) || strings.HasPrefix(start, rest) {
				kind := SearchGrep
				if strings.Contains(start, "--files") {
					kind = SearchGlob
				}
				return kind, true, true
			}
		}
		return "", false, false
	}
	kind, ok := searchKind(rest)
	if !ok {
		return "", false, false
	}
	if e.Cwd == "" || e.CwdTruncated || !filepath.IsAbs(e.Cwd) {
		return kind, true, true
	}
	return kind + " " + filepath.Clean(e.Cwd), false, true
}

// foldSearches rewrites the exec of OpenCode's own ripgrep, and its exit,
// to the search's target: only the first exec of a process whose parent
// the stream does not show started, the harness itself. An rg the agent
// runs through bash is a child of a command and keeps its text, so the
// command's claim covers it.
func foldSearches(g models.GroundTruth, started map[uint32]bool) models.GroundTruth {
	execd := map[uint32]bool{}
	search := map[uint32]models.GroundTruthEvent{}
	var out models.GroundTruth
	for _, e := range g {
		switch e.ActionType {
		case models.ProcessExec:
			first := !execd[e.PID]
			execd[e.PID] = true
			if first && !started[e.PPID] {
				if t, cut, ok := searchTarget(e); ok {
					e.Target, e.TargetTruncated = t, cut
					search[e.PID] = e
				}
			}
		case models.ProcessExit:
			if s, ok := search[e.PID]; ok {
				e.Target, e.TargetTruncated = s.Target, s.TargetTruncated
			}
		}
		out = append(out, e)
	}
	return out
}
