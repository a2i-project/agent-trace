package scripts

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// scripts/baseline-review.py groups a baseline's rules for a person (I-164):
// commands (a multi-line one by its first line), hosts and requests, files
// outside the workspace by directory with their action types on one line,
// files in the workspace, what each command did beneath it and the
// sensitive changes; with --against only what the other baseline lacks.
func TestTheBaselineReviewGroupsTheRules(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	_, here, _, _ := runtime.Caller(0)
	script := filepath.Join(filepath.Dir(here), "..", "..", "scripts", "baseline-review.py")
	tmp := t.TempDir()
	interactive := filepath.Join(tmp, "interactive.json")
	write(t, interactive, `{"schema":1,"agent":"claude-code","agent_version":"2.1.306","mode":"interactive","runs":5,"min_agreement":0.2,
"rules":[
 {"action_type":"process_exec","target":"gh auth token"},{"action_type":"process_exit","target":"gh auth token"},
 {"action_type":"process_exec","target":"/bin/bash -c env"},
 {"action_type":"process_exec","target":"/bin/sh -c x\ny\nz"},
 {"action_type":"net_connect","target":"downloads.claude.ai"},{"action_type":"net_connect","target":"api.anthropic.com"},
 {"action_type":"file_open","target":"/h/.claude/history.jsonl"},{"action_type":"file_write","target":"/h/.claude/history.jsonl"},
 {"action_type":"file_open","target":"/etc/hosts"},
 {"action_type":"file_open","target":"{workspace}/a.txt"},
 {"action_type":"git_commit","target":"x"}],
"subtrees":[{"command":"/bin/bash -c env","events":[{"action_type":"process_exec","target":"/usr/bin/env"}]},
 {"command":"gh auth token","events":[{"action_type":"net_connect","target":"api.github.com"}]}],
"sensitive":{"files":["~/.claude.json"],"changes":[{"file":"~/.claude.json","key":["projects","{workspace}"],"kind":"added"}]}}`, 0o644)
	printBase := filepath.Join(tmp, "print.json")
	write(t, printBase, `{"schema":1,"agent":"claude-code","agent_version":"2.1.306","runs":5,"min_agreement":0.2,
"rules":[{"action_type":"process_exec","target":"/bin/bash -c env"},{"action_type":"net_connect","target":"api.anthropic.com"},
 {"action_type":"file_open","target":"/etc/hosts"},{"action_type":"file_open","target":"/h/.claude/history.jsonl"}],
"subtrees":[{"command":"/bin/bash -c env","events":[{"action_type":"process_exec","target":"/usr/bin/env"}]}]}`, 0o644)

	b, err := exec.Command("python3", script, interactive).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	out := string(b)
	for _, w := range []string{
		"mode interactive, 11 rule(s) from 5 control run(s)",
		"commands run (3):\n  /bin/bash -c env\n  /bin/sh -c x  (+2 more lines)\n  gh auth token\n",
		"hosts and requests (2):\n  net_connect      api.anthropic.com\n  net_connect      downloads.claude.ai\n",
		"files outside the workspace (2), by directory:\n  /etc/\n    hosts  open\n  /h/.claude/\n    history.jsonl  open, write\n",
		"files in the workspace (1):\n  {workspace}/a.txt  open\n",
		"other (1):\n  git_commit       x\n",
		"beneath baselined commands (2 command(s)):\n  /bin/bash -c env:\n    process_exec     /usr/bin/env\n  gh auth token:\n    net_connect      api.github.com\n",
		"sensitive-file changes (1):\n  ~/.claude.json  projects.{workspace}  added",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("review lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "process_exit") {
		t.Errorf("a command's exit is listed:\n%s", out)
	}

	b, err = exec.Command("python3", script, interactive, "--against", printBase).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	out = string(b)
	for _, w := range []string{
		"against:         " + printBase + " (claude-code 2.1.306, mode print, 4 rule(s)",
		"commands run (2):\n  /bin/sh -c x  (+2 more lines)\n  gh auth token\n",
		"hosts and requests (1):\n  net_connect      downloads.claude.ai\n",
		"files outside the workspace (1), by directory:\n  /h/.claude/\n    history.jsonl  write\n",
		"beneath baselined commands (1 command(s)):\n  gh auth token:\n",
		"sensitive-file changes (1):",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("review --against lacks %q:\n%s", w, out)
		}
	}
	if b, err := exec.Command("python3", script, filepath.Join(tmp, "none.json")).CombinedOutput(); err == nil || !strings.Contains(string(b), "cannot read") {
		t.Errorf("a missing baseline: %v %s", err, b)
	}
}
