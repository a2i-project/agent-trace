package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/agent"
)

// The per-agent settings of the analysis (each agent's label and task
// groups) live in a protocol file (config/protocol.json), apart from the
// agents' operational profiles (config/agents.json), so that the command
// names no agent (E-8). The file holds no target or bar: the analysis
// reports measurements (E-11). Every results file records the file's
// SHA-256.

// ProtocolFileName is the file's name; by default it is read beside the
// agent config.
const ProtocolFileName = "protocol.json"

// protocolSchema is the only schema the command reads.
const protocolSchema = 1

// Protocol is a loaded protocol file.
type Protocol struct {
	Schema int `json:"schema"`
	// Registration identifies the registration the numbers belong to.
	Registration string       `json:"protocol"`
	Agents       []AgentEntry `json:"agents"`
	// CaptureUser says whether the campaign's runs must have run the agent
	// as a user other than the operator (I-139).
	CaptureUser *CaptureUser `json:"capture_user"`

	path   string
	sha256 string
	byName map[string]*AgentEntry
}

// AgentEntry is one agent's entry. Every field is required; a task list
// without tasks is [].
type AgentEntry struct {
	// Agent is the adapter's name, as the campaign manifest records it.
	Agent string `json:"agent"`
	// Label names the agent in the report's text.
	Label string `json:"label"`
	// ToolHeavyTasks are the tasks whose claims include harness-shared
	// reads (background-command output Reads, V-36): the named subgroup and
	// the mislocation stratum of decision D5. A held-out task counts by its
	// name after the prefix.
	ToolHeavyTasks *[]string `json:"tool_heavy_tasks"`
	// D8HeldOutTasks are the tasks decision D8 holds out for the agent, as
	// the report's description of the task groups names them. The held-out
	// scope itself is the runner's heldout: prefix (IsHeldOut).
	D8HeldOutTasks *[]string `json:"d8_held_out_tasks"`

	toolHeavy map[string]bool
}

// CaptureUser is either the requirement (RequireOtherUser, with the
// decision it comes from) or its declared absence (None, with the reason):
// every run of the campaign records the user its agent ran as (run_as),
// and that user is not the operator.
type CaptureUser struct {
	RequireOtherUser bool   `json:"require_other_user,omitempty"`
	Basis            string `json:"basis,omitempty"`
	None             string `json:"none,omitempty"`
}

// ProtocolPath is the file the command reads: an explicit path, else
// protocol.json beside the agent config.
func ProtocolPath(explicit, agentConfig string) string {
	if explicit != "" {
		return explicit
	}
	return filepath.Join(filepath.Dir(agentConfig), ProtocolFileName)
}

// LoadProtocol reads and validates a protocol file. It refuses unknown
// fields, trailing data, a missing field and an agent no adapter is
// registered under.
func LoadProtocol(path string) (*Protocol, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("protocol file: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Protocol
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("protocol file %s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("protocol file %s: data after the top-level object", path)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("protocol file %s: %w", path, err)
	}
	p.path, p.sha256 = path, fileSHA256(path)
	return &p, nil
}

func (p *Protocol) validate() error {
	if p.Schema != protocolSchema {
		return fmt.Errorf("schema %d, want %d", p.Schema, protocolSchema)
	}
	if p.Registration == "" {
		return errors.New("no protocol: name the registration the numbers belong to")
	}
	if len(p.Agents) == 0 {
		return errors.New("no agents")
	}
	switch u := p.CaptureUser; {
	case u == nil:
		return errors.New("no capture_user: give require_other_user with its basis, or none with the reason")
	case u.RequireOtherUser == (u.None != ""):
		return errors.New("capture_user: give either require_other_user (with basis) or none, not both or neither")
	case u.RequireOtherUser && u.Basis == "":
		return errors.New("capture_user: require_other_user without the basis it comes from")
	case u.None != "" && u.Basis != "":
		return errors.New("capture_user: basis without require_other_user")
	}
	p.byName = map[string]*AgentEntry{}
	for i := range p.Agents {
		a := &p.Agents[i]
		if err := a.validate(); err != nil {
			return fmt.Errorf("agents[%d] (%q): %w", i, a.Agent, err)
		}
		if p.byName[a.Agent] != nil {
			return fmt.Errorf("agent %q listed twice", a.Agent)
		}
		p.byName[a.Agent] = a
	}
	return nil
}

func (a *AgentEntry) validate() error {
	if a.Agent == "" {
		return errors.New("no agent name")
	}
	if _, ok := agent.Lookup(a.Agent); !ok {
		return fmt.Errorf("no adapter is registered under %q (registered: %s)", a.Agent, strings.Join(agent.Names(), ", "))
	}
	if a.Label == "" {
		return errors.New("no label")
	}
	var err error
	if a.toolHeavy, err = taskSet("tool_heavy_tasks", a.ToolHeavyTasks); err != nil {
		return err
	}
	if _, err = taskSet("d8_held_out_tasks", a.D8HeldOutTasks); err != nil {
		return err
	}
	return nil
}

// taskSet checks a required task list ([] for none) and returns it as a set.
func taskSet(field string, tasks *[]string) (map[string]bool, error) {
	if tasks == nil {
		return nil, fmt.Errorf("no %s: list the tasks, [] for none", field)
	}
	set := map[string]bool{}
	for _, t := range *tasks {
		switch {
		case t == "":
			return nil, fmt.Errorf("%s: an empty task name", field)
		case strings.HasPrefix(t, HeldOutPrefix):
			return nil, fmt.Errorf("%s: %q: name the task without the %s prefix", field, t, HeldOutPrefix)
		case set[t]:
			return nil, fmt.Errorf("%s: %q listed twice", field, t)
		}
		set[t] = true
	}
	return set, nil
}

// Entry returns an agent's entry; ok is false for an agent the file does
// not list.
func (p *Protocol) Entry(agentName string) (*AgentEntry, bool) {
	a, ok := p.byName[agentName]
	return a, ok
}

// Require fails for any of the agents the file does not list, naming the
// file, so an agent with no entry is never analysed against a default.
func (p *Protocol) Require(agents []string) error {
	var missing []string
	seen := map[string]bool{}
	for _, a := range agents {
		if _, ok := p.byName[a]; !ok && !seen[a] {
			seen[a] = true
			missing = append(missing, a)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the protocol file %s has no entry for agent(s) %s of the campaign: add one for each before analysing", filepath.Base(p.path), strings.Join(missing, ", "))
	}
	return nil
}

// RequireCaptureUser fails, naming the file and the runs, when the file
// requires the capture user (I-139) and a run of the campaign does not
// record one, or records the operator's uid, so a campaign whose agent
// could read the operator's home is never analysed as an experiment.
func (p *Protocol) RequireCaptureUser(c *Campaign) error {
	if p.CaptureUser == nil || !p.CaptureUser.RequireOtherUser {
		return nil
	}
	var bad []string
	for _, r := range c.Manifest.Runs {
		switch a := r.RunAs; {
		case a == nil || a.User == "" || a.UID == nil:
			bad = append(bad, c.ID(r)+" (no run_as)")
		case a.OperatorUID == nil:
			bad = append(bad, c.ID(r)+" (no operator uid)")
		case *a.UID == *a.OperatorUID:
			bad = append(bad, c.ID(r)+" (ran as the operator)")
		}
	}
	if len(bad) == 0 {
		return nil
	}
	shown := bad
	if len(shown) > 5 {
		shown = append(shown[:5:5], fmt.Sprintf("and %d more", len(bad)-5))
	}
	return fmt.Errorf("the protocol file %s requires every run to have run the agent as a user other than the operator (capture_user, %s), and %d of %d run(s) did not: %s; capture with --run-as (scripts/setup-capture-user.sh), or analyse a campaign that is not an experiment with a protocol file whose capture_user is none",
		filepath.Base(p.path), p.CaptureUser.Basis, len(bad), len(c.Manifest.Runs), strings.Join(shown, ", "))
}

// IsToolHeavy says whether a task is in an agent's tool-heavy subgroup. A
// held-out task counts by its name after the prefix, so heldout:long-cc is
// tool-heavy when long-cc is.
func (p *Protocol) IsToolHeavy(agentName, task string) bool {
	a, ok := p.byName[agentName]
	return ok && a.toolHeavy[strings.TrimPrefix(task, HeldOutPrefix)]
}

// heldOutLine describes decision D8's held-out tasks per agent for the
// report, in file order.
func (p *Protocol) heldOutLine() string {
	var parts []string
	for _, a := range p.Agents {
		if len(*a.D8HeldOutTasks) == 0 {
			continue
		}
		var ts []string
		for _, t := range *a.D8HeldOutTasks {
			ts = append(ts, "`"+t+"`")
		}
		parts = append(parts, a.Label+" "+joinAnd(ts))
	}
	return strings.Join(parts, ", ")
}

// joinAnd joins a list as prose: "a", "a and b", "a, b and c".
func joinAnd(xs []string) string {
	if len(xs) <= 1 {
		return strings.Join(xs, "")
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}
