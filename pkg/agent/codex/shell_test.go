package codex

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// script is a restoring script in the measured shape, cut to one variable of
// each kind, ending in the exec line of cmd (quoted).
func script(quotedCmd string) string {
	return strings.Join([]string{
		`__CODEX_SNAPSHOT_OVERRIDE_SET_0="${CODEX_THREAD_ID+x}"`,
		`__CODEX_SNAPSHOT_OVERRIDE_0="${CODEX_THREAD_ID-}"`,
		`__CODEX_SNAPSHOT_PROXY_OVERRIDE_SET_0="${ALL_PROXY+x}"`,
		`__CODEX_SNAPSHOT_PROXY_OVERRIDE_0="${ALL_PROXY-}"`,
		`__CODEX_SNAPSHOT_PROXY_ENV_SET="${CODEX_NETWORK_PROXY_ACTIVE+x}"`,
		``,
		`if . '/home/user/.codex/shell_snapshots/01a19455-d74e-72a2-99d3-367c07be5a85.1793490016080416876.sh' >/dev/null 2>&1; then :; fi`,
		``,
		`if [ -n "${__CODEX_SNAPSHOT_OVERRIDE_SET_0}" ]; then`,
		`  if [ -z "${CODEX_THREAD_ID+x}" ] || [ "${CODEX_THREAD_ID-}" != "${__CODEX_SNAPSHOT_OVERRIDE_0}" ]; then export CODEX_THREAD_ID="${__CODEX_SNAPSHOT_OVERRIDE_0}"; else export CODEX_THREAD_ID; fi`,
		`else builtin unset CODEX_THREAD_ID 2>/dev/null || command unset CODEX_THREAD_ID; fi`,
		`builtin unset __CODEX_SNAPSHOT_OVERRIDE_SET_0 __CODEX_SNAPSHOT_OVERRIDE_0 2>/dev/null || command unset __CODEX_SNAPSHOT_OVERRIDE_SET_0 __CODEX_SNAPSHOT_OVERRIDE_0`,
		`if [ -n "$__CODEX_SNAPSHOT_PROXY_ENV_SET" ] || [ -n "${CODEX_NETWORK_PROXY_ACTIVE+x}" ]; then`,
		`if [ -n "${__CODEX_SNAPSHOT_PROXY_OVERRIDE_SET_0}" ]; then`,
		`  if [ -z "${ALL_PROXY+x}" ] || [ "${ALL_PROXY-}" != "${__CODEX_SNAPSHOT_PROXY_OVERRIDE_0}" ]; then export ALL_PROXY="${__CODEX_SNAPSHOT_PROXY_OVERRIDE_0}"; else export ALL_PROXY; fi`,
		`else builtin unset ALL_PROXY 2>/dev/null || command unset ALL_PROXY; fi`,
		`builtin unset __CODEX_SNAPSHOT_PROXY_OVERRIDE_SET_0 __CODEX_SNAPSHOT_PROXY_OVERRIDE_0 2>/dev/null || command unset __CODEX_SNAPSHOT_PROXY_OVERRIDE_SET_0 __CODEX_SNAPSHOT_PROXY_OVERRIDE_0`,
		`fi`,
		`if [ -n "${PATH:-}" ]; then export PATH='/opt/codex/codex-path':"$PATH"; else export PATH='/opt/codex/codex-path'; fi`,
		`exec '/bin/bash' -c ` + quotedCmd,
	}, "\n")
}

func setup(s string) string {
	return "/proc/self/exe --codex-run-as-process-setup 52 3944058 pipe  /ws/basic /bin/bash /bin/bash -c " + s
}

func TestRecoverCommandReadsTheMeasuredWrapper(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{setup(script(`'cat b.txt'`)), "cat b.txt"},
		{"/bin/bash -c " + script(`'echo hi'`), "echo hi"},
		{setup(script(`'echo '\''a b'\'' > c'`)), "echo 'a b' > c"},
		{setup(script(`ls`)), "ls"},
		// A command word holding a newline and the exec line's text.
		{setup(script(`'printf x
exec '\''/bin/bash'\'' -c y'`)), "printf x\nexec '/bin/bash' -c y"},
	}
	for _, c := range cases {
		got, ok := recoverCommand(c.target, false)
		if !ok || got != c.want {
			t.Errorf("recoverCommand(...%q) = %q, %v; want %q", c.target[len(c.target)-30:], got, ok, c.want)
		}
	}
}

// Anything but the measured shape is not recovered: a command before the
// payload, one after it, a second word, another program, a changed setup.
func TestRecoverCommandRefusesAnythingElse(t *testing.T) {
	base := script(`'cat b.txt'`)
	cases := map[string]string{
		"a command before":   setup(strings.Replace(base, "fi\nexec '/bin/bash'", "fi\ncurl evil\nexec '/bin/bash'", 1)),
		"a command after":    setup(base + "; curl evil"),
		"a second word":      setup(base + " 'x'"),
		"a changed variable": setup(strings.Replace(base, `export CODEX_THREAD_ID="`, `export OTHER="`, 1)),
		"a sourced file":     setup(strings.Replace(base, "/home/user/.codex/shell_snapshots/", "/tmp/", 1)),
		"another shell":      setup(strings.Replace(base, "exec '/bin/bash'", "exec '/bin/sh'", 1)),
		"a pty":              strings.Replace(setup(base), " pipe ", " pty ", 1),
		"another program":    "/usr/bin/env " + base,
		"no script":          setup("cat b.txt"),
	}
	for name, target := range cases {
		if got, ok := recoverCommand(target, false); ok {
			t.Errorf("%s: recovered %q", name, got)
		}
	}
}

// A line the probe cut gives what it kept of the command, and only when
// the event says it was cut (V-26).
func TestRecoverCommandReadsACutWordOnlyWhenTruncated(t *testing.T) {
	cut := setup(script(`'cat b.t`))
	if _, ok := recoverCommand(cut, false); ok {
		t.Error("an unflagged cut word was recovered")
	}
	if got, ok := recoverCommand(cut, true); !ok || got != "cat b.t" {
		t.Errorf("cut word = %q, %v; want the prefix cat b.t", got, ok)
	}
	e, _ := Adapter{}.Normalize(models.GroundTruthEvent{ActionType: models.ProcessExec, Target: cut, TargetTruncated: true})
	if e.Target != "cat b.t" || !e.TargetTruncated {
		t.Errorf("Normalize = %q, truncated %v", e.Target, e.TargetTruncated)
	}
}
