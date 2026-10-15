// Command status reports whether this machine's agents are at versions the
// adapters were verified against (I-57): per adapter in config/agents.json,
// the configured versions, the version of the agent installed on PATH and
// whether it is one of them; and the kernel version against the probes'
// stated minimums. It runs each agent's --version and nothing else.
//
// Exit codes: 0 every installed agent is at a configured version; 1 an
// installed agent's version is not configured or could not be read; 2 with
// --agent, that agent is not on PATH; 3 usage or config error. The kernel
// check is printed and does not change the exit code.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/config"
)

const (
	exitUnconfigured = 1
	exitAbsent       = 2
	exitError        = 3
)

// kernelNeed is one probe's stated kernel minimum.
type kernelNeed struct {
	probe        string
	major, minor int
	why          string
}

// kernelNeeds are the minimums the probe pages state: the fs probe's
// FAN_REPORT_NAME (12_probe_fs.md, Known limits) and the net probe's
// bpf_probe_read_kernel (13_probe_net.md). The proc probe's page states none.
var kernelNeeds = []kernelNeed{
	{"fs", 5, 9, "fanotify FAN_REPORT_DFID_NAME"},
	{"net", 5, 5, "bpf_probe_read_kernel"},
}

// env is what status reads from the machine, replaced in tests.
type env struct {
	lookPath func(string) (string, error)
	version  func(path string) (string, error)
	kernel   func() (string, error)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, machine()))
}

func machine() env {
	return env{lookPath: exec.LookPath, version: agentVersion, kernel: kernelRelease}
}

var versionRE = regexp.MustCompile(`[0-9]+(\.[0-9]+)+`)

// agentVersion runs `<path> --version` and takes the first version-shaped
// word of its output: `2.1.296 (Claude Code)` and `1.3.4` both give the
// version.
func agentVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s --version: %v %s", path, err, strings.TrimSpace(stderr.String()))
	}
	v := versionRE.FindString(stdout.String())
	if v == "" {
		return "", fmt.Errorf("%s --version printed no version: %q", path, strings.TrimSpace(stdout.String()))
	}
	return v, nil
}

func kernelRelease() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(u.Release[:]), nil
}

var releaseRE = regexp.MustCompile(`^([0-9]+)\.([0-9]+)`)

func run(args []string, out, errOut io.Writer, e env) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var configPath, only string
	fs.StringVar(&configPath, "config", "", "Agent version config. Default: $"+config.EnvVar+", else "+config.RelPath+" beside the binary or in the checkout above the working directory")
	fs.StringVar(&only, "agent", "", "Check only this adapter's agent, and exit 2 when it is not on PATH")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(errOut, "status: unexpected argument %q\n", fs.Arg(0))
		return exitError
	}
	cfg, err := config.LoadDefault(configPath)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "status: %v\n", err)
		return exitError
	}
	names := cfg.Names()
	if only != "" {
		if !cfg.Has(only) {
			_, _ = fmt.Fprintf(errOut, "status: %s has no entry for %q (it has %s)\n", cfg.Path, only, strings.Join(names, ", "))
			return exitError
		}
		names = []string{only}
	}
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(out, format, a...) }

	p("config: %s\n", cfg.Path)
	printKernel(out, e)

	code := 0
	for _, name := range names {
		a := cfg.Adapters[name]
		parts := make([]string, len(a.Versions))
		for i, v := range a.Versions {
			parts[i] = fmt.Sprintf("%s (verified %s, %d fixture(s))", v.Version, v.Verified, len(v.Fixtures))
		}
		configured := strings.Join(parts, ", ")
		if configured == "" {
			configured = "none"
		}
		p("%s: configured %s\n", name, configured)
		path, err := e.lookPath(a.Binary)
		if err != nil {
			p("  installed: %s not found on PATH\n", a.Binary)
			if only != "" {
				code = exitAbsent
			}
			continue
		}
		v, err := e.version(path)
		switch {
		case err != nil:
			p("  installed: %s, version unknown: %v\n", path, err)
			code = exitUnconfigured
		case cfg.Configured(name, v):
			p("  installed: %s at %s: configured\n", v, path)
		default:
			p("  installed: %s at %s: NOT CONFIGURED; verify a capture of it before trusting its verdicts (I-57)\n", v, path)
			code = exitUnconfigured
		}
	}
	return code
}

func printKernel(w io.Writer, e env) {
	rel, err := e.kernel()
	if err != nil {
		_, _ = fmt.Fprintf(w, "kernel: unknown (%v)\n", err)
		return
	}
	_, _ = fmt.Fprintf(w, "kernel: %s\n", rel)
	major, minor, err := parseRelease(rel)
	for _, n := range kernelNeeds {
		verdict := "ok"
		switch {
		case err != nil:
			verdict = "unknown (" + err.Error() + ")"
		case major < n.major || (major == n.major && minor < n.minor):
			verdict = "BELOW"
		}
		_, _ = fmt.Fprintf(w, "  %s probe needs %d.%d or later (%s): %s\n", n.probe, n.major, n.minor, n.why, verdict)
	}
}

func parseRelease(rel string) (int, int, error) {
	m := releaseRE.FindStringSubmatch(rel)
	if m == nil {
		return 0, 0, errors.New("release " + strconv.Quote(rel) + " has no major.minor")
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major, minor, nil
}
