package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testConfig = `{"schema":1,"adapters":{
 "claude-code":{"binary":"claude","versions":[{"version":"2.1.286","verified":"2026-10-12","fixtures":["a"]},{"version":"2.1.296","verified":"2026-10-13","fixtures":["b","c"]}]},
 "gemini":{"binary":"agy","versions":[{"version":"1.3.4","verified":"2026-10-13","fixtures":["d"]}]}}}`

func fakeEnv(installed map[string]string, kernel string) env {
	return env{
		lookPath: func(bin string) (string, error) {
			if _, ok := installed[bin]; !ok {
				return "", errors.New("not found")
			}
			return "/bin/" + bin, nil
		},
		version: func(path string) (string, error) {
			v := installed[filepath.Base(path)]
			if v == "" {
				return "", errors.New("--version failed")
			}
			return v, nil
		},
		kernel: func() (string, error) { return kernel, nil },
	}
}

func TestStatus(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "agents.json")
	if err := os.WriteFile(cfg, []byte(testConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		args      []string
		installed map[string]string
		kernel    string
		code      int
		want      []string
	}{
		{"both configured", nil, map[string]string{"claude": "2.1.296", "agy": "1.3.4"}, "6.17.0-41-generic", 0,
			[]string{"claude-code: configured 2.1.286 (verified 2026-10-12, 1 fixture(s)), 2.1.296 (verified 2026-10-13, 2 fixture(s))", "installed: 2.1.296 at /bin/claude: configured", "installed: 1.3.4 at /bin/agy: configured", "kernel: 6.17.0-41-generic", "fs probe needs 5.9 or later (fanotify FAN_REPORT_DFID_NAME): ok"}},
		{"one not configured", nil, map[string]string{"claude": "2.1.300", "agy": "1.3.4"}, "6.17.0", 1,
			[]string{"installed: 2.1.300 at /bin/claude: NOT CONFIGURED"}},
		{"absent agents are not a failure", nil, map[string]string{}, "6.17.0", 0,
			[]string{"claude not found on PATH", "agy not found on PATH"}},
		{"version unreadable", nil, map[string]string{"claude": ""}, "6.17.0", 1,
			[]string{"installed: /bin/claude, version unknown"}},
		{"one agent, configured", []string{"--agent", "gemini"}, map[string]string{"claude": "9.9.9", "agy": "1.3.4"}, "6.17.0", 0,
			[]string{"gemini: configured 1.3.4"}},
		{"one agent, absent", []string{"--agent", "claude-code"}, map[string]string{"agy": "1.3.4"}, "6.17.0", exitAbsent,
			[]string{"claude not found on PATH"}},
		{"old kernel is reported, not an exit", nil, map[string]string{}, "5.4.0-200-generic", 0,
			[]string{"fs probe needs 5.9 or later (fanotify FAN_REPORT_DFID_NAME): BELOW", "net probe needs 5.5 or later (bpf_probe_read_kernel): BELOW"}},
		{"kernel between the minimums", nil, map[string]string{}, "5.8.1", 0,
			[]string{"fs probe needs 5.9 or later (fanotify FAN_REPORT_DFID_NAME): BELOW", "net probe needs 5.5 or later (bpf_probe_read_kernel): ok"}},
		{"unparsable kernel", nil, map[string]string{}, "weird", 0,
			[]string{"unknown (release \"weird\" has no major.minor)"}},
		{"unknown adapter", []string{"--agent", "nope"}, nil, "6.17.0", exitError, nil},
		{"stray argument", []string{"x"}, nil, "6.17.0", exitError, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(append([]string{"--config", cfg}, tc.args...), &out, &errOut, fakeEnv(tc.installed, tc.kernel))
			if code != tc.code {
				t.Errorf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.code, out.String(), errOut.String())
			}
			for _, w := range tc.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output lacks %q:\n%s", w, out.String())
				}
			}
		})
	}
}

func TestStatusMissingConfigIsAnError(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--config", filepath.Join(t.TempDir(), "none.json")}, &out, &errOut, fakeEnv(nil, "6.17.0")); code != exitError {
		t.Errorf("exit %d, want %d", code, exitError)
	}
}

// TestStatusReadsTheRepositoryConfig: run from the package directory with no
// flag, the checkout's config/agents.json is found.
func TestStatusReadsTheRepositoryConfig(t *testing.T) {
	t.Setenv("AGENT_TRACE_CONFIG", "")
	var out, errOut bytes.Buffer
	code := run(nil, &out, &errOut, fakeEnv(map[string]string{}, "6.17.0"))
	if code != 0 || !strings.Contains(out.String(), filepath.Join("config", "agents.json")) {
		t.Errorf("exit %d\n%s%s", code, out.String(), errOut.String())
	}
}
