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

// The per-agent targets of the analysis live in a protocol file
// (config/protocol.json), apart from the agents' operational profiles
// (config/agents.json), so that the command names no agent (E-8). Every
// results file records the file's SHA-256.

// ProtocolFileName is the file's name; by default it is read beside the
// agent config.
const ProtocolFileName = "protocol.json"

// protocolSchema is the only schema the command reads.
const protocolSchema = 1

// Protocol is a loaded protocol file.
type Protocol struct {
	Schema int `json:"schema"`
	// Registration identifies the registration the numbers belong to.
	Registration string         `json:"protocol"`
	Agents       []AgentTargets `json:"agents"`

	path   string
	sha256 string
	byName map[string]*AgentTargets
}

// AgentTargets are one agent's targets. Every field is required: a target
// the protocol does not set for an agent is declared absent with a reason,
// never left out.
type AgentTargets struct {
	// Agent is the adapter's name, as the campaign manifest records it.
	Agent string `json:"agent"`
	// Label names the agent in the report's text.
	Label string `json:"label"`
	// FaithfulBar is H3d's practicality bar (decision D2).
	FaithfulBar *FaithfulBar `json:"faithful_bar"`
	// InconclusiveRange is H3c's pilot-informed range of the INCONCLUSIVE
	// rate: reported against, never a refutation criterion.
	InconclusiveRange *PilotRange `json:"inconclusive_pilot_range"`
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

// FaithfulBar is either a bar (MinRate, with the decision it comes from) or
// its declared absence (None, the reason the report prints).
type FaithfulBar struct {
	MinRate *float64 `json:"min_rate,omitempty"`
	Basis   string   `json:"basis,omitempty"`
	None    string   `json:"none,omitempty"`
}

// PilotRange is either a range (Low to High, inclusive) or its declared
// absence (None, with the reason).
type PilotRange struct {
	Low  *float64 `json:"low,omitempty"`
	High *float64 `json:"high,omitempty"`
	None string   `json:"none,omitempty"`
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
// fields, trailing data, a missing target and an agent no adapter is
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
	p.byName = map[string]*AgentTargets{}
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

func (a *AgentTargets) validate() error {
	if a.Agent == "" {
		return errors.New("no agent name")
	}
	if _, ok := agent.Lookup(a.Agent); !ok {
		return fmt.Errorf("no adapter is registered under %q (registered: %s)", a.Agent, strings.Join(agent.Names(), ", "))
	}
	if a.Label == "" {
		return errors.New("no label")
	}
	switch b := a.FaithfulBar; {
	case b == nil:
		return errors.New("no faithful_bar: give min_rate and basis, or none with the reason")
	case (b.MinRate != nil) == (b.None != ""):
		return errors.New("faithful_bar: give either min_rate (with basis) or none, not both or neither")
	case b.MinRate != nil && (*b.MinRate <= 0 || *b.MinRate > 1):
		return fmt.Errorf("faithful_bar: min_rate %v is not in (0, 1]", *b.MinRate)
	case b.MinRate != nil && b.Basis == "":
		return errors.New("faithful_bar: min_rate without the basis it comes from")
	case b.None != "" && b.Basis != "":
		return errors.New("faithful_bar: basis without min_rate")
	}
	switch r := a.InconclusiveRange; {
	case r == nil:
		return errors.New("no inconclusive_pilot_range: give low and high, or none with the reason")
	case r.None != "" && (r.Low != nil || r.High != nil):
		return errors.New("inconclusive_pilot_range: give either low and high or none, not both")
	case r.None == "" && (r.Low == nil || r.High == nil):
		return errors.New("inconclusive_pilot_range: give both low and high, or none with the reason")
	case r.None == "" && (*r.Low < 0 || *r.Low > *r.High || *r.High > 1):
		return fmt.Errorf("inconclusive_pilot_range: need 0 <= low <= high <= 1, got %v to %v", *r.Low, *r.High)
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

// Targets returns an agent's targets; ok is false for an agent the file
// does not list.
func (p *Protocol) Targets(agentName string) (*AgentTargets, bool) {
	a, ok := p.byName[agentName]
	return a, ok
}

// Require fails for any of the agents the file does not list, naming the
// file, so an agent with no targets is never analysed against a default.
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
		return fmt.Errorf("the protocol file %s has no targets for agent(s) %s of the campaign: add an entry for each (declaring a target absent with none where the protocol sets none) before analysing", filepath.Base(p.path), strings.Join(missing, ", "))
	}
	return nil
}

// IsToolHeavy says whether a task is in an agent's tool-heavy subgroup. A
// held-out task counts by its name after the prefix, so heldout:long-cc is
// tool-heavy when long-cc is.
func (p *Protocol) IsToolHeavy(agentName, task string) bool {
	a, ok := p.byName[agentName]
	return ok && a.toolHeavy[strings.TrimPrefix(task, HeldOutPrefix)]
}

// InRange says whether an INCONCLUSIVE rate is inside the agent's pilot
// range; nil when the agent has none.
func (a *AgentTargets) InRange(rate float64) *bool {
	r := a.InconclusiveRange
	if r.None != "" {
		return nil
	}
	in := rate >= *r.Low && rate <= *r.High
	return &in
}

// barKey is the results.json key of an agent's FAITHFUL bar.
func barKey(agentName string) string {
	return "h3d_" + strings.ReplaceAll(agentName, "-", "_") + "_bar"
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
