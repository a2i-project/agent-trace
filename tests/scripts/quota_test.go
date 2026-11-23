package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// quotaClaude wraps the fake claude: while $FAKE_DIR/quota.n is below
// FAKE_QUOTA_TIMES, a task run (not a control, not the warm-up) prints
// FAKE_QUOTA, with @RESET@ replaced by the epoch two seconds ahead, on stderr
// and exits 1, as an agent stopped by its account's quota does.
const quotaClaude = `#!/usr/bin/env bash
if [ "$1" != --version ] && [ -n "${FAKE_QUOTA:-}" ]; then
  case "${@: -1}" in
    *agent-trace-control-marker*|"Run the shell command true with the Bash tool"*) ;;
    *)
      n=$(cat "$FAKE_DIR/quota.n" 2>/dev/null || echo 0)
      if [ "$n" -lt "${FAKE_QUOTA_TIMES:-1}" ]; then
        echo $((n + 1)) >"$FAKE_DIR/quota.n"
        echo "${FAKE_QUOTA//@RESET@/$(( $(date +%s) + 2 ))}" >&2
        echo '[]' >"$FAKE_DIR/events.json"
        exit 1
      fi ;;
  esac
fi
exec "$(dirname "$0")/claude-real" "$@"
`

type quotaManifest struct {
	Runs []struct {
		Agent  string `json:"agent"`
		Status string `json:"status"`
	} `json:"runs"`
	Attempts []struct {
		Agent     string         `json:"agent"`
		Status    string         `json:"status"`
		Exclusion map[string]any `json:"exclusion"`
	} `json:"attempts"`
	Slots []struct {
		Agent string `json:"agent"`
		State string `json:"state"`
		X4    int    `json:"x4"`
	} `json:"slots"`
	QuotaInterrupted int            `json:"quota_interrupted"`
	QuotaPaused      map[string]any `json:"quota_paused"`
}

// quotaCampaign lays out a campaign of claude-code and gemini (agy) with the
// quota-injecting claude, edits the profiles, runs the campaign and returns
// its log, its manifest and the output directory.
func quotaCampaign(t *testing.T, plan string, extraEnv []string, prepare func(root, tmp, out string)) (string, quotaManifest, string) {
	t.Helper()
	root, tmp, env := layout(t, "")
	_, here, _, _ := runtime.Caller(0)
	copyFile(t, filepath.Join(filepath.Dir(here), "..", "..", "scripts", "capture-campaign.sh"), filepath.Join(root, "scripts", "capture-campaign.sh"), 0o755)
	bin := filepath.Join(tmp, "bin")
	if err := os.Rename(filepath.Join(bin, "claude"), filepath.Join(bin, "claude-real")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(bin, "claude"), quotaClaude, 0o755)
	write(t, filepath.Join(bin, "make"), "#!/bin/sh\nexit 0\n", 0o755)
	write(t, filepath.Join(tmp, "plan.txt"), plan, 0o644)
	out := filepath.Join(tmp, "campaign")
	if prepare != nil {
		prepare(root, tmp, out)
	}
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-campaign.sh"), "--controls", "1", "--seed", "7",
		"--allow-unconfigured-version", filepath.Join(tmp, "plan.txt"), out)
	cmd.Env = append(env, "DBUS_SESSION_BUS_ADDRESS=unix:path="+filepath.Join(tmp, "bus"), "XDG_RUNTIME_DIR="+tmp,
		"CAMPAIGN_QUOTA_MARGIN=1", "CAMPAIGN_QUOTA_BACKOFF_MIN=1", "CAMPAIGN_QUOTA_BACKOFF_MAX=2")
	cmd.Env = append(cmd.Env, extraEnv...)
	b, err := cmd.CombinedOutput()
	log := string(b)
	if err != nil {
		t.Fatalf("campaign: %v\n%s", err, log)
	}
	var m quotaManifest
	mb, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil || json.Unmarshal(mb, &m) != nil {
		t.Fatalf("manifest: %v\n%s", err, log)
	}
	return log, m, out
}

func checkAllOK(t *testing.T, m quotaManifest, runs int, log string) {
	t.Helper()
	if len(m.Runs) != runs {
		t.Fatalf("%d runs, want %d\n%s", len(m.Runs), runs, log)
	}
	for _, r := range m.Runs {
		if r.Status != "ok" {
			t.Errorf("a %s run is %s\n%s", r.Agent, r.Status, log)
		}
	}
	for _, s := range m.Slots {
		if s.State != "ok" || s.X4 != 0 {
			t.Errorf("slot %+v: want ok with no X4 attempt", s)
		}
	}
	if len(m.QuotaPaused) != 0 {
		t.Errorf("still paused: %v", m.QuotaPaused)
	}
}

// A quota error that states its reset time pauses only its agent's queue:
// the other agent's slot is recorded meanwhile, the slot is recorded again
// after the reset, and the attempt is XQ, outside the attempt budget
// (I-169).
func TestAQuotaErrorPausesOnlyItsAgentAndResumesAfterTheReset(t *testing.T) {
	log, m, out := quotaCampaign(t, "claude-code basic 1\ngemini basic 2\n",
		[]string{"FAKE_QUOTA=Claude AI usage limit reached|@RESET@", "FAKE_QUOTA_TIMES=1"}, nil)
	checkAllOK(t, m, 3, log)
	if m.QuotaInterrupted != 1 || len(m.Attempts) != 1 || m.Attempts[0].Exclusion["rule"] != "XQ" ||
		m.Attempts[0].Exclusion["reason"] != "quota" || m.Attempts[0].Exclusion["reset"] == nil || m.Attempts[0].Status != "quota-interrupted" {
		t.Errorf("quota_interrupted %d, attempts %+v", m.QuotaInterrupted, m.Attempts)
	}
	pause := strings.Index(log, "claude-code's queue is paused until")
	agy := strings.Index(log, "=== gemini ")
	resume := strings.Index(log, "=== quota: claude-code resumes")
	if pause < 0 || resume < 0 || agy < 0 {
		t.Fatalf("pause %d, gemini slot %d, resume %d\n%s", pause, agy, resume, log)
	}
	// Plan order (seed 7) puts claude-code first: gemini runs while it is paused.
	if pause > agy || agy > resume {
		t.Errorf("gemini's slot did not run during claude-code's pause\n%s", log)
	}
	ev, _ := os.ReadFile(filepath.Join(out, "quota", "events.jsonl"))
	if !strings.Contains(string(ev), `"kind": "reset"`) || !strings.Contains(string(ev), `"how": "reset time passed"`) {
		t.Errorf("events.jsonl:\n%s", ev)
	}
	sum, _ := os.ReadFile(filepath.Join(out, "summary.txt"))
	if !strings.Contains(string(sum), "quota-interrupted attempts (XQ, set aside, not in the attempt budget): 1 (quota 1, host-down 0)") {
		t.Errorf("summary.txt:\n%s", sum)
	}
}

// Without a reset time the agent waits a back-off, then the profile's
// preflight probes; a failed probe doubles the back-off, a passing one
// resumes the agent (I-169).
func TestAQuotaErrorWithoutAResetTimeIsProbedByThePreflight(t *testing.T) {
	log, m, out := quotaCampaign(t, "claude-code basic 2\n",
		[]string{"FAKE_QUOTA=API Error: rate limit exceeded", "FAKE_QUOTA_TIMES=1"},
		func(root, tmp, out string) {
			editProfile(t, root, "claude-code", func(p map[string]any) {
				// Fails the first time it runs, passes after.
				p["quota"] = map[string]any{"preflight": []any{"sh", "-c", `n=$(cat "$FAKE_DIR/pf" 2>/dev/null || echo 0); echo $((n + 1)) >"$FAKE_DIR/pf"; [ "$n" -ge 1 ]`}}
			})
		})
	checkAllOK(t, m, 2, log)
	if m.QuotaInterrupted != 1 {
		t.Errorf("quota_interrupted %d\n%s", m.QuotaInterrupted, log)
	}
	for _, want := range []string{"claude-code's preflight failed (exit 1); next probe in 2s", "claude-code's preflight passed; it resumes",
		"every slot left (2) belongs to a paused agent (claude-code)"} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q\n%s", want, log)
		}
	}
	ev, _ := os.ReadFile(filepath.Join(out, "quota", "events.jsonl"))
	if !strings.Contains(string(ev), `"how": "preflight passed"`) || !strings.Contains(string(ev), `"why": "preflight exit 1"`) {
		t.Errorf("events.jsonl:\n%s", ev)
	}
}

// An attempt left without a run.json (the VM or the host went down inside
// it) is recorded as XQ host-down when the same command runs again, and its
// slot is recorded again without spending its attempt budget (I-169).
func TestAnAttemptCutByAHostDownIsQuotaInterrupted(t *testing.T) {
	log, m, _ := quotaCampaign(t, "claude-code basic 1\n", nil, func(root, tmp, out string) {
		write(t, filepath.Join(out, "claude-code-2.1.306", "basic", "run-01", "campaign.log"), "cut\n", 0o644)
	})
	checkAllOK(t, m, 1, log)
	if m.QuotaInterrupted != 1 || len(m.Attempts) != 1 || m.Attempts[0].Exclusion["reason"] != "host-down" {
		t.Errorf("quota_interrupted %d, attempts %+v\n%s", m.QuotaInterrupted, m.Attempts, log)
	}
}
