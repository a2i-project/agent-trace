package gemini

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// The wrapper as the process probe recorded it under strace of agy 1.3.4 on
// 2026-10-13 (I-47): the harness execs `bash -c <CommandLine>`, found on PATH,
// as a child of the agy process. A command whose stdout is a pipe or a file
// keeps its text after the prefix, quotes and all.
func TestNormalizeRecoversTheCommandFromTheBashWrapper(t *testing.T) {
	a := Adapter{}
	for _, c := range []struct{ observed, want string }{
		{"/usr/bin/bash -c echo hi", "echo hi"},
		{"/bin/bash -c cat a.txt", "cat a.txt"},
		{"/usr/bin/bash -c sleep 2; echo 'a  b' | tr a-z A-Z > out.txt", "sleep 2; echo 'a  b' | tr a-z A-Z > out.txt"},
		{"/usr/bin/bash -c printf 'x\\n'\necho two", "printf 'x\\n'\necho two"},
	} {
		for _, at := range []models.ActionType{models.ProcessExec, models.ProcessExit} {
			got, keep := a.Normalize(models.GroundTruthEvent{ActionType: at, Target: c.observed})
			if !keep || got.Target != c.want {
				t.Errorf("Normalize(%s %q) = %q, %v; want %q", at, c.observed, got.Target, keep, c.want)
			}
		}
	}
}

// Anything that is not exactly the wrapper keeps its text, so a program the
// harness ran some other way, or another shell, shows as itself (D6).
func TestNormalizeLeavesEverythingElseAlone(t *testing.T) {
	a := Adapter{}
	for _, observed := range []string{
		"/usr/bin/grep -l --binary-files=without-match -F -r -- seed .",
		"/usr/bin/bash -c ",              // nothing after the wrapper
		"/usr/bin/bash -lc echo hi",      // another flag
		"/usr/bin/sh -c echo hi",         // another shell
		"/tmp/bash -c echo hi",           // a bash elsewhere
		"/usr/bin/bash  -c echo hi",      // another spacing
		"x /usr/bin/bash -c echo hi",     // the wrapper inside another line
		"/usr/local/bin/bash -c echo hi", // not where it was seen
	} {
		got, keep := a.Normalize(models.GroundTruthEvent{ActionType: models.ProcessExec, Target: observed})
		if !keep || got.Target != observed {
			t.Errorf("Normalize(%q) = %q, %v; want it unchanged", observed, got.Target, keep)
		}
	}
	// File targets are never read as commands.
	f := models.GroundTruthEvent{ActionType: models.FileOpen, Target: "/usr/bin/bash -c echo hi"}
	if got, _ := a.Normalize(f); got.Target != f.Target {
		t.Errorf("a file target was rewritten to %q", got.Target)
	}
}

// A wrapper the probe cut keeps its prefix, which the verifier pairs as a
// prefix of the claim (V-26); the flag stays.
func TestNormalizeRecoversThePrefixOfATruncatedWrapper(t *testing.T) {
	got, _ := Adapter{}.Normalize(models.GroundTruthEvent{ActionType: models.ProcessExec, Target: "/usr/bin/bash -c python3 -c 'print(1", TargetTruncated: true})
	if got.Target != "python3 -c 'print(1" || !got.TargetTruncated {
		t.Errorf("truncated wrapper = %q (truncated %v)", got.Target, got.TargetTruncated)
	}
}

func TestNormalizeDropsTheDeletedSuffix(t *testing.T) {
	got, _ := Adapter{}.Normalize(models.GroundTruthEvent{ActionType: models.FileDelete, Target: "/home/u/.gemini/antigravity-cli/crashes/crash_1_x.log (deleted)"})
	if got.Target != "/home/u/.gemini/antigravity-cli/crashes/crash_1_x.log" {
		t.Errorf("target = %q", got.Target)
	}
}

// The paths are the ones the strace of one print-mode run of agy 1.3.4 showed
// the harness writing (I-48).
func TestHarnessOwnedDirectories(t *testing.T) {
	a := Adapter{}
	for _, p := range []string{
		"/home/u/.gemini/antigravity-cli",
		"/home/u/.gemini/antigravity-cli/conversations/fe5c14b8-1dfe-480f-ac10-d772c8892143.db-wal",
		"/home/u/.gemini/antigravity-cli/brain/fe5c14b8-1dfe-480f-ac10-d772c8892143/.system_generated/steps/6/output.txt",
		"/home/u/.gemini/antigravity-cli/bin/agentapi",
		"/home/u/.cache/antigravity/bin/rg_embedded-14d1066b44c4f6b7",
		"/home/u/.local/bin/.update_test3033112475",
		"/root/.gemini/antigravity-cli/cache/last_conversations.json",
		"/tmp/unleash-repo-schema-v1-codeium-language-server.json",
	} {
		if !a.IsHarnessOwned(p) {
			t.Errorf("%s is the harness's", p)
		}
	}
	for _, p := range []string{
		"/home/u/.local/bin/agy", // the binary: a write there is a finding
		"/home/u/.local/bin/.update_test",
		"/home/u/.gemini/settings.json", // the Gemini CLI's, not agy's
		"/home/u/.gemini/antigravity-cli-other/x",
		"/home/u/.cache/antigravity-x",
		"/ws/.agents/agents/agent-trace/agent.md", // the project's
		"/tmp/unleash-repo-schema-v1-codeium-language-server.json.bak",
		"/home/a/b/.gemini/antigravity-cli/x",
	} {
		if a.IsHarnessOwned(p) {
			t.Errorf("%s is not the harness's", p)
		}
	}
}

func TestCanonicalReplacesThePerRunIDs(t *testing.T) {
	a := Adapter{}
	const app = "/home/u/.gemini/antigravity-cli/"
	for _, c := range []struct{ in, want string }{
		{app + "conversations/fe5c14b8-1dfe-480f-ac10-d772c8892143.db-wal", app + "conversations/{id}.db-wal"},
		{app + "brain/fe5c14b8-1dfe-480f-ac10-d772c8892143/.system_generated/steps/16/output.txt", app + "brain/{id}/.system_generated/steps/{n}/output.txt"},
		// The step's directory itself, whose create the probe reports as an
		// ambiguous write of the directory (I-49).
		{app + "brain/fe5c14b8-1dfe-480f-ac10-d772c8892143/.system_generated/steps/4", app + "brain/{id}/.system_generated/steps/{n}"},
		{app + "brain/fe5c14b8-1dfe-480f-ac10-d772c8892143/.system_generated/steps/10/", app + "brain/{id}/.system_generated/steps/{n}/"},
		{app + "brain/fe5c14b8-1dfe-480f-ac10-d772c8892143/.system_generated/steps/4x", app + "brain/{id}/.system_generated/steps/4x"},
		{app + "brain/fe5c14b8-1dfe-480f-ac10-d772c8892143/.system_generated/logs/chunks/transcript_full/00000000.jsonl", app + "brain/{id}/.system_generated/logs/chunks/transcript_full/{n}.jsonl"},
		{app + "crashes/crash_1564584_1645188e-697d-4e88-9d59-5fa12fc728f4.log", app + "crashes/crash_{pid}_{id}.log"},
		{app + "cache/last_conversations.json.1645188e-697d-4e88-9d59-5fa12fc728f4.tmp", app + "cache/last_conversations.json.{id}.tmp"},
		{app + "bin/agentapi", app + "bin/agentapi"},
		{app + "log/cli-20261013_212554.log", app + "log/cli-{time}.log"},
		{"/home/u/.cache/antigravity/bin/.rg_embedded-2404865066", "/home/u/.cache/antigravity/bin/.rg_embedded-{n}"},
		{"/home/u/.local/bin/.update_test3033112475", "/home/u/.local/bin/.update_test{n}"},
		{"/dev/pts/11", "/dev/pts/{n}"},
		// Outside the harness's files nothing changes.
		{"/ws/steps/16/fe5c14b8-1dfe-480f-ac10-d772c8892143", "/ws/steps/16/fe5c14b8-1dfe-480f-ac10-d772c8892143"},
		{"/home/u/.local/bin/agy", "/home/u/.local/bin/agy"},
	} {
		got := a.Canonical(models.GroundTruthEvent{ActionType: models.FileWrite, Target: c.in})
		if got.Target != c.want {
			t.Errorf("Canonical(%q) = %q, want %q", c.in, got.Target, c.want)
		}
	}
	// A process target is not a path.
	p := models.GroundTruthEvent{ActionType: models.ProcessExec, Target: "/dev/pts/11"}
	if got := a.Canonical(p); got.Target != p.Target {
		t.Errorf("a process target was canonicalised to %q", got.Target)
	}
}

// agy declares the one host its process connected to in only some runs of the
// paired capture, its access-token refresh (I-52). A host the baseline
// explains in every run is not declared, and no declaration is an address.
func TestHarnessHostsAreTheMeasuredOccasionalHosts(t *testing.T) {
	got := Adapter{}.HarnessHosts()
	if len(got) != 1 || got[0] != "oauth2.googleapis.com" {
		t.Errorf("HarnessHosts() = %v, want only oauth2.googleapis.com", got)
	}
}
