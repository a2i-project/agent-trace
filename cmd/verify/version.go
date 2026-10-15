package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/config"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The agent version check (I-57): the session's agent version against the
// versions config/agents.json lists for the adapter. By default an
// unconfigured version is a WARNING line and a JSON field, and the verdict is
// unchanged; --strict-version makes the run INCONCLUSIVE instead.

// Version check states, as the JSON report's agent_version_check gives them.
const (
	versionConfigured        = "configured"
	versionNotConfigured     = "not configured"
	versionAdapterUnlisted   = "adapter not configured"
	versionUnknown           = "unknown"
	versionNotApplicable     = "not applicable"
	versionNoConfig          = "no config"
	versionSourceSession     = "session"
	versionSourceFlag        = "--agent-version"
	strictVersionFlagName    = "strict-version"
	agentVersionFlagName     = "agent-version"
	versionConfigFlagName    = "config"
	versionCheckDecisionNote = "I-57"
)

type versionFlags struct {
	strict  bool
	version string
	config  string
}

func addVersionFlags(fs *flag.FlagSet) *versionFlags {
	f := &versionFlags{}
	fs.BoolVar(&f.strict, strictVersionFlagName, false, "Make the run INCONCLUSIVE when the session's agent version is not in the agent version config, or is not known (I-57). Without it, an unconfigured version is a WARNING and the verdict is unchanged")
	fs.StringVar(&f.version, agentVersionFlagName, "", "Version of the agent that recorded the session, for a format that does not state it (agy's). A session that states another version is an error")
	fs.StringVar(&f.config, versionConfigFlagName, "", "Agent version config. Default: $"+config.EnvVar+", else "+config.RelPath+" beside the binary or in the checkout above the working directory")
	return f
}

// versionCheck is the result of the check, for the report.
type versionCheck struct {
	adapter    string
	version    string
	source     string
	state      string
	configPath string
	configured []string
	strict     bool
}

// checkVersion compares the session's version with the config. It fails on a
// config that exists but cannot be read, on a missing config under
// --strict-version, and on an --agent-version that contradicts the session.
func checkVersion(f *versionFlags, adapter string, rep agent.Report) (versionCheck, error) {
	c := versionCheck{adapter: adapter, version: rep.AgentVersion, strict: f.strict}
	if c.version != "" {
		c.source = versionSourceSession
	}
	if f.version != "" {
		if c.version != "" && c.version != f.version {
			return c, fmt.Errorf("--%s %s, but the session was recorded by %s version %s", agentVersionFlagName, f.version, adapter, c.version)
		}
		if c.version == "" {
			c.version, c.source = f.version, versionSourceFlag
		}
	}
	if adapter == agent.GenericName {
		c.state = versionNotApplicable
		return c, nil
	}
	cfg, err := config.LoadDefault(f.config)
	switch {
	case errors.Is(err, config.ErrNotFound) && !f.strict:
		c.state = versionNoConfig
		return c, nil
	case err != nil:
		return c, err
	}
	c.configPath = cfg.Path
	c.configured = cfg.Versions(adapter)
	switch {
	case !cfg.Has(adapter):
		c.state = versionAdapterUnlisted
	case c.version == "":
		c.state = versionUnknown
	case cfg.Configured(adapter, c.version):
		c.state = versionConfigured
	default:
		c.state = versionNotConfigured
	}
	return c, nil
}

// reason is why --strict-version makes the run INCONCLUSIVE, or "" when it
// does not.
func (c versionCheck) reason() string {
	switch c.state {
	case versionNotConfigured:
		return fmt.Sprintf("the session was recorded by %s version %s, which %s does not configure (configured: %s): the adapter was verified on those versions only (--%s, %s)", c.adapter, c.version, c.configPath, strings.Join(c.configured, ", "), strictVersionFlagName, versionCheckDecisionNote)
	case versionAdapterUnlisted:
		return fmt.Sprintf("%s has no entry for the %s adapter, so no version of it is verified (--%s, %s)", c.configPath, c.adapter, strictVersionFlagName, versionCheckDecisionNote)
	case versionUnknown:
		return fmt.Sprintf("the session does not state the %s version and --%s was not given, so it cannot be checked against %s (--%s, %s)", c.adapter, agentVersionFlagName, c.configPath, strictVersionFlagName, versionCheckDecisionNote)
	}
	return ""
}

// applyStrict makes the verdict INCONCLUSIVE under --strict-version when the
// version is not configured or not known. Findings stay listed; the verdict
// no longer asserts them, since an adapter that does not fit the version can
// make them.
func (c versionCheck) applyStrict(v verification.Verdict) verification.Verdict {
	r := c.reason()
	if !c.strict || r == "" {
		return v
	}
	if n := v.Findings(); n > 0 {
		r += fmt.Sprintf("; the %d finding(s) above may come from that", n)
	}
	v.Outcome = verification.OutcomeInconclusive
	v.Faithful = false
	v.Reasons = append([]string{r}, v.Reasons...)
	return v
}

// printVersionCheck prints the WARNING line near the top of the report. A
// configured, unknown or inapplicable version prints nothing; an unknown one
// is in the JSON report, and under --strict-version in the verdict's reasons.
func printVersionCheck(w io.Writer, c versionCheck) {
	tail := "the verdict is unchanged; --" + strictVersionFlagName + " makes it INCONCLUSIVE"
	if c.strict {
		tail = "--" + strictVersionFlagName + " makes the run INCONCLUSIVE"
	}
	switch c.state {
	case versionNotConfigured:
		_, _ = fmt.Fprintf(w, "WARNING: %s version %s is not configured in %s (configured: %s); the adapter was verified on those versions only and may not fit this one; %s (%s)\n", c.adapter, c.version, c.configPath, strings.Join(c.configured, ", "), tail, versionCheckDecisionNote)
	case versionAdapterUnlisted:
		_, _ = fmt.Fprintf(w, "WARNING: %s has no entry for the %s adapter, so no version of it is verified; %s (%s)\n", c.configPath, c.adapter, tail, versionCheckDecisionNote)
	case versionNoConfig:
		_, _ = fmt.Fprintf(w, "WARNING: %v, so the %s version is not checked (%s)\n", config.ErrNotFound, c.adapter, versionCheckDecisionNote)
	}
}

// versionJSON is the check in the JSON report, embedded in jsonReport.
type versionJSON struct {
	// AgentVersion is the version checked, from the session or from
	// --agent-version (AgentVersionSource); absent when neither gives one.
	AgentVersion       string `json:"agent_version,omitempty"`
	AgentVersionSource string `json:"agent_version_source,omitempty"`
	// AgentVersionConfigured is absent when it could not be decided: no
	// version, the generic adapter, or no config.
	AgentVersionConfigured *bool  `json:"agent_version_configured,omitempty"`
	AgentVersionCheck      string `json:"agent_version_check"`
}

func (c versionCheck) json() versionJSON {
	j := versionJSON{AgentVersion: c.version, AgentVersionSource: c.source, AgentVersionCheck: c.state}
	switch c.state {
	case versionConfigured:
		t := true
		j.AgentVersionConfigured = &t
	case versionNotConfigured, versionAdapterUnlisted:
		if c.version != "" {
			f := false
			j.AgentVersionConfigured = &f
		}
	}
	return j
}
