package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// H1: how often the existing tools accept the attacks (protocol section 4).
// The comparison harnesses are not reimplemented: this reads the output
// directory of scripts/compare/sweep.py (results.jsonl, summary.json,
// run.json).

// Outcomes a sweep row can carry.
const (
	OutAccepted         = "accepted"
	OutDetected         = "detected"
	OutNotRepresentable = "not_representable"
	OutRefused          = "attack_refused"
	OutInapplicable     = "inapplicable"
	OutError            = "error"
)

// Attack kinds as the sweep names them.
var H1Kinds = []string{"omission", "fabrication", "substitution", "interval-widening"}

// SweepRow is one line of results.jsonl.
type SweepRow struct {
	Tool      string `json:"tool"`
	Condition string `json:"condition"`
	Attacker  string `json:"attacker"`
	Kind      string `json:"kind"`
	Fixture   string `json:"fixture"`
	Seed      *int   `json:"seed"`
	N         *int   `json:"n"`
	Mutation  string `json:"mutation"`
	Outcome   string `json:"outcome"`
	Status    string `json:"status"`
}

// sweepCell is one cell of summary.json.
type sweepCell struct {
	Tool         string `json:"tool"`
	Condition    string `json:"condition"`
	Attacker     string `json:"attacker"`
	Kind         string `json:"kind"`
	Fixture      string `json:"fixture"`
	ControlsHeld bool   `json:"controls_held"`
	Controls     int    `json:"controls"`
}

// H1Row is one row of the H1 table: a tool row and an attack kind.
type H1Row struct {
	Tool      string `json:"tool"`
	Condition string `json:"condition"`
	Attacker  string `json:"attacker,omitempty"`
	// Kind is an attack kind, or "*" for all four.
	Kind string `json:"kind"`
	// Considered counts every sweep row of the cell; Evaluated those the
	// tool judged (accepted or detected) with controls that held; Accepted is
	// the numerator.
	Considered       int `json:"considered"`
	Evaluated        int `json:"evaluated"`
	Accepted         int `json:"accepted"`
	Detected         int `json:"detected"`
	NotRepresentable int `json:"not_representable"`
	Refused          int `json:"attack_refused"`
	Inapplicable     int `json:"inapplicable"`
	Errors           int `json:"errors"`
	// Unjudged counts judged rows set aside because their cell's controls
	// did not hold: the row is reported as UNJUDGED and not counted.
	Unjudged int `json:"unjudged"`
	Sessions int `json:"sessions"`
	Distinct int `json:"distinct_mutations"`
	// Acceptance is accepted over evaluated with a bootstrap over sessions
	// (fixtures).
	Acceptance ClusterRate `json:"acceptance"`
	// Status is "UNJUDGED" when no cell of the row had controls that held.
	Status string `json:"status,omitempty"`
}

// H1Measure is the measurement of one tool row of protocol section 4 (H1a to
// H1d): the share of attacked trajectories it accepts.
type H1Measure struct {
	ID      string `json:"id"`
	Row     string `json:"row"`
	Measure string `json:"measure"`
	State   string `json:"state"`
	Value   string `json:"value"`
	// Acceptance is accepted over evaluated with a bootstrap over sessions
	// (fixtures).
	Acceptance ClusterRate `json:"acceptance"`
}

// H1Control is one control row: it shows the harness can produce a
// rejection and does not test H1.
type H1Control struct {
	Tool      string `json:"tool"`
	Condition string `json:"condition"`
	Attacker  string `json:"attacker,omitempty"`
	Kind      string `json:"kind"`
	Evaluated int    `json:"evaluated"`
	Detected  int    `json:"detected"`
	Accepted  int    `json:"accepted"`
	// Held says the control behaved as registered: the rows named
	// `expect` all had that outcome.
	Expect string `json:"expect"`
	Held   bool   `json:"held"`
}

// EditSplit is the edit criterion's detection on Write and Edit mutations,
// reported, not tested.
type EditSplit struct {
	EditMutations        int               `json:"edit_mutations"`
	EditDetected         int               `json:"edit_detected"`
	EditDetectionRate    *float64          `json:"edit_detection_rate"`
	BySeed               map[string][2]int `json:"by_seed_detected_evaluated,omitempty"`
	NonEditMutations     int               `json:"non_edit_mutations"`
	NonEditDetected      int               `json:"non_edit_detected"`
	NotSplitByFinalState string            `json:"final_state_split"`
}

// H1Results is the whole H1 section.
type H1Results struct {
	Dir           string      `json:"directory"`
	Commit        string      `json:"agent_trace_commit,omitempty"`
	Dirty         bool        `json:"agent_trace_dirty,omitempty"`
	Params        any         `json:"sweep_params,omitempty"`
	Tools         any         `json:"tools_manifest,omitempty"`
	HarnessErrors int         `json:"harness_errors"`
	Rows          []H1Row     `json:"rows"`
	Controls      []H1Control `json:"controls"`
	// ControlRows lists the rows (honest, drop-not-resealed, ...) by outcome.
	ControlRowCounts map[string]map[string]int `json:"control_row_outcomes"`
	Measures         []H1Measure               `json:"measures"`
	EditSplit        *EditSplit                `json:"edit_criterion_detection"`
	NaiveCommandA3   *H1Row                    `json:"command_criterion_naive_a3,omitempty"`
}

func isControlKind(kind string) bool { return kind == "honest" || strings.HasPrefix(kind, "control-") }

func readSweepRows(path string) ([]SweepRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var rows []SweepRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r SweepRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		rows = append(rows, r)
	}
	return rows, sc.Err()
}

type rowKey struct{ tool, condition, attacker, kind string }

// cellKey is a sweep cell (a fixture of a tool row and kind).
type cellKey struct {
	rowKey
	fixture string
}

// BuildH1 reads a sweep output directory and builds the H1 section. It
// returns an error when the directory lacks results.jsonl or summary.json.
func BuildH1(dir string) (*H1Results, error) {
	rows, err := readSweepRows(filepath.Join(dir, "results.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read the comparison sweep: %w", err)
	}
	var summary struct {
		Cells         []sweepCell `json:"cells"`
		HarnessErrors int         `json:"harness_errors"`
	}
	sdata, err := os.ReadFile(filepath.Join(dir, "summary.json"))
	if err != nil {
		return nil, fmt.Errorf("read the comparison sweep: %w", err)
	}
	if err := json.Unmarshal(sdata, &summary); err != nil {
		return nil, fmt.Errorf("parse summary.json: %w", err)
	}
	held := map[cellKey]bool{}
	for _, c := range summary.Cells {
		held[cellKey{rowKey{c.Tool, c.Condition, c.Attacker, c.Kind}, c.Fixture}] = c.ControlsHeld
	}
	res := &H1Results{Dir: filepath.Base(filepath.Clean(dir)), HarnessErrors: summary.HarnessErrors, ControlRowCounts: map[string]map[string]int{}}
	if rd, err := os.ReadFile(filepath.Join(dir, "run.json")); err == nil {
		var run struct {
			AgentTrace struct {
				Commit string `json:"commit"`
				Dirty  bool   `json:"dirty"`
			} `json:"agent_trace"`
			Tools  any `json:"tools"`
			Params any `json:"params"`
		}
		if json.Unmarshal(rd, &run) == nil {
			res.Commit, res.Dirty, res.Tools, res.Params = run.AgentTrace.Commit, run.AgentTrace.Dirty, run.Tools, run.Params
		}
	}

	type acc struct {
		H1Row
		fixtures map[string]*[2]float64 // fixture -> accepted, evaluated
		distinct map[string]bool
	}
	table := map[rowKey]*acc{}
	pooled := map[rowKey]*acc{}
	controls := map[rowKey]*H1Control{}
	get := func(m map[rowKey]*acc, k rowKey) *acc {
		a := m[k]
		if a == nil {
			a = &acc{H1Row: H1Row{Tool: k.tool, Condition: k.condition, Attacker: k.attacker, Kind: k.kind}, fixtures: map[string]*[2]float64{}, distinct: map[string]bool{}}
			m[k] = a
		}
		return a
	}
	var editSeedRows []SweepRow
	for _, r := range rows {
		if r.Tool == "harness" {
			continue
		}
		if isControlKind(r.Kind) {
			if res.ControlRowCounts[r.Tool+"/"+r.Condition+"/"+r.Kind] == nil {
				res.ControlRowCounts[r.Tool+"/"+r.Condition+"/"+r.Kind] = map[string]int{}
			}
			res.ControlRowCounts[r.Tool+"/"+r.Condition+"/"+r.Kind][r.Outcome]++
			continue
		}
		k := rowKey{r.Tool, r.Condition, r.Attacker, r.Kind}
		for _, a := range []*acc{get(table, k), get(pooled, rowKey{r.Tool, r.Condition, r.Attacker, "*"})} {
			a.Considered++
			switch r.Outcome {
			case OutNotRepresentable:
				a.NotRepresentable++
			case OutRefused:
				a.Refused++
			case OutInapplicable:
				a.Inapplicable++
			case OutError:
				a.Errors++
			case OutAccepted, OutDetected:
				if !held[cellKey{k, r.Fixture}] {
					a.Unjudged++
					continue
				}
				a.Evaluated++
				fx := a.fixtures[r.Fixture]
				if fx == nil {
					fx = &[2]float64{}
					a.fixtures[r.Fixture] = fx
				}
				fx[1]++
				if r.Outcome == OutAccepted {
					a.Accepted++
					fx[0]++
				} else {
					a.Detected++
				}
				a.distinct[r.Fixture+"|"+r.Mutation] = true
			}
		}
		// Controls that are rows of the table (witness checkpoint, other key).
		if r.Outcome == OutAccepted || r.Outcome == OutDetected {
			if (r.Tool == ToolHalo && r.Condition == "witness-checkpoint") || (r.Tool == ToolSignet && r.Condition == "other-key") {
				c := controls[k]
				if c == nil {
					c = &H1Control{Tool: r.Tool, Condition: r.Condition, Attacker: r.Attacker, Kind: r.Kind, Expect: OutDetected}
					controls[k] = c
				}
				c.Evaluated++
				if r.Outcome == OutDetected {
					c.Detected++
				} else {
					c.Accepted++
				}
			}
		}
		if r.Tool == ToolRT && r.Condition == "edit-criterion" && r.Attacker == "adaptive" {
			editSeedRows = append(editSeedRows, r)
		}
	}
	flush := func(m map[rowKey]*acc) []H1Row {
		keys := make([]rowKey, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return less4(keys[i], keys[j]) })
		var out []H1Row
		for _, k := range keys {
			a := m[k]
			r := a.H1Row
			r.Sessions = len(a.fixtures)
			r.Distinct = len(a.distinct)
			var clusters []Cluster
			for _, fx := range sortedFixtures(a.fixtures) {
				clusters = append(clusters, Cluster{Den: a.fixtures[fx][1], Nums: []float64{a.fixtures[fx][0]}})
			}
			r.Acceptance = ClusterBootstrap(clusters, 1, BootstrapResamples, BootstrapSeed)[0]
			if r.Evaluated == 0 && r.Unjudged > 0 {
				r.Status = "UNJUDGED"
			}
			out = append(out, r)
		}
		return out
	}
	res.Rows = append(flush(table), flush(pooled)...)
	sort.SliceStable(res.Rows, func(i, j int) bool {
		a, b := res.Rows[i], res.Rows[j]
		return less4(rowKey{a.Tool, a.Condition, a.Attacker, orderKind(a.Kind)}, rowKey{b.Tool, b.Condition, b.Attacker, orderKind(b.Kind)})
	})
	ckeys := make([]rowKey, 0, len(controls))
	for k := range controls {
		ckeys = append(ckeys, k)
	}
	sort.Slice(ckeys, func(i, j int) bool { return less4(ckeys[i], ckeys[j]) })
	for _, k := range ckeys {
		c := controls[k]
		c.Held = c.Evaluated > 0 && c.Detected == c.Evaluated
		res.Controls = append(res.Controls, *c)
	}
	res.EditSplit = buildEditSplit(editSeedRows, held)
	for i := range res.Rows {
		r := res.Rows[i]
		if r.Tool == ToolRT && r.Condition == "command-criterion" && r.Attacker == "naive" && r.Kind == "substitution" {
			res.NaiveCommandA3 = &r
		}
	}
	res.Measures = measureH1(res, rows, held)
	return res, nil
}

func orderKind(k string) string {
	for i, x := range H1Kinds {
		if x == k {
			return fmt.Sprintf("%d", i)
		}
	}
	return "9" + k
}

func less4(a, b rowKey) bool {
	if a.tool != b.tool {
		return a.tool < b.tool
	}
	if a.condition != b.condition {
		return a.condition < b.condition
	}
	if a.attacker != b.attacker {
		return a.attacker < b.attacker
	}
	return a.kind < b.kind
}

func sortedFixtures(m map[string]*[2]float64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// editTools are the tools the edit criterion reads (it skips NotebookEdit).
var editTools = map[string]bool{"Write": true, "Edit": true}

// isEditMutation says whether any mutated claim of a sweep row's mutation
// record came from a Write or Edit call. The record is the JSON list of
// cmd/attack's mutations.
func isEditMutation(mutation string) bool {
	var ms []struct {
		Before *struct {
			Tool string `json:"tool"`
		} `json:"before"`
		After *struct {
			Tool string `json:"tool"`
		} `json:"after"`
	}
	if json.Unmarshal([]byte(mutation), &ms) != nil {
		return false
	}
	for _, m := range ms {
		if (m.Before != nil && editTools[m.Before.Tool]) || (m.After != nil && editTools[m.After.Tool]) {
			return true
		}
	}
	return false
}

func buildEditSplit(rows []SweepRow, held map[cellKey]bool) *EditSplit {
	e := &EditSplit{BySeed: map[string][2]int{}, NotSplitByFinalState: "not computed: the sweep rows do not record whether a mutation changes the replayed final state"}
	for _, r := range rows {
		if r.Outcome != OutAccepted && r.Outcome != OutDetected {
			continue
		}
		if r.Kind == "interval-widening" || !held[cellKey{rowKey{r.Tool, r.Condition, r.Attacker, r.Kind}, r.Fixture}] {
			continue
		}
		if isEditMutation(r.Mutation) {
			e.EditMutations++
			seed := "none"
			if r.Seed != nil {
				seed = fmt.Sprintf("%d", *r.Seed)
			}
			s := e.BySeed[seed]
			s[1]++
			if r.Outcome == OutDetected {
				e.EditDetected++
				s[0]++
			}
			e.BySeed[seed] = s
		} else {
			e.NonEditMutations++
			if r.Outcome == OutDetected {
				e.NonEditDetected++
			}
		}
	}
	e.EditDetectionRate = ratioPtr(e.EditDetected, e.EditMutations)
	return e
}

// measureH1 measures the four registered tool rows: how many attacked
// trajectories each accepts. A row whose cells' controls did not hold, or
// whose control row did not reject every kind, is UNJUDGED: its numbers do
// not measure acceptance.
func measureH1(res *H1Results, rows []SweepRow, held map[cellKey]bool) []H1Measure {
	controlHeld := func(tool, cond string) (bool, bool) {
		any := false
		for _, c := range res.Controls {
			if c.Tool == tool && c.Condition == cond {
				any = true
				if !c.Held {
					return false, true
				}
			}
		}
		return true, any
	}
	// count tallies the judged outcomes of a tool row over the attack kinds
	// that pass keep, per fixture for the bootstrap.
	type tally struct {
		accepted, detected, evaluated, unjudged int
		fixtures                                map[string]*[2]float64
	}
	count := func(tool, cond, attacker string, keep func(SweepRow) bool) tally {
		t := tally{fixtures: map[string]*[2]float64{}}
		for _, r := range rows {
			if r.Tool != tool || r.Condition != cond || isControlKind(r.Kind) || (attacker != "" && r.Attacker != attacker) || !keep(r) {
				continue
			}
			if r.Outcome != OutAccepted && r.Outcome != OutDetected {
				continue
			}
			if !held[cellKey{rowKey{r.Tool, r.Condition, r.Attacker, r.Kind}, r.Fixture}] {
				t.unjudged++
				continue
			}
			t.evaluated++
			fx := t.fixtures[r.Fixture]
			if fx == nil {
				fx = &[2]float64{}
				t.fixtures[r.Fixture] = fx
			}
			fx[1]++
			if r.Outcome == OutAccepted {
				t.accepted++
				fx[0]++
			} else {
				t.detected++
			}
		}
		return t
	}
	all := func(SweepRow) bool { return true }
	measure := func(id, row, what string, t tally, ctlTool, ctlCond string) H1Measure {
		c := H1Measure{ID: id, Row: row, Measure: what}
		var clusters []Cluster
		for _, fx := range sortedFixtures(t.fixtures) {
			clusters = append(clusters, Cluster{Den: t.fixtures[fx][1], Nums: []float64{t.fixtures[fx][0]}})
		}
		c.Acceptance = ClusterBootstrap(clusters, 1, BootstrapResamples, BootstrapSeed)[0]
		ctlOK, ctlAny := true, false
		if ctlTool != "" {
			ctlOK, ctlAny = controlHeld(ctlTool, ctlCond)
		}
		counts := fmt.Sprintf("accepted %s over %d session(s); detected %d", crText(c.Acceptance), len(t.fixtures), t.detected)
		switch {
		case t.evaluated == 0 && t.unjudged > 0:
			c.State, c.Value = Unjudged, fmt.Sprintf("%d row(s) set aside: the cells' controls did not hold", t.unjudged)
		case t.evaluated == 0:
			c.State, c.Value = NotMeasured, "no judged row in the sweep"
		case !ctlOK:
			c.State, c.Value = Unjudged, counts+"; a control row did not behave as registered ("+ctlTool+" "+ctlCond+" must reject every kind)"
		default:
			c.State, c.Value = Measured, counts
		}
		if t.unjudged > 0 && c.State != Unjudged {
			c.Value += fmt.Sprintf("; %d row(s) UNJUDGED and not counted", t.unjudged)
		}
		if ctlTool != "" && !ctlAny {
			c.Value += "; its control row is absent from the sweep"
		}
		return c
	}
	var out []H1Measure
	out = append(out, measure("H1a", "halo-record, chain re-sealed, no checkpoint (no-checkpoint)", "acceptance of A1 to A4",
		count(ToolHalo, "no-checkpoint", "", all), ToolHalo, "witness-checkpoint"))
	out = append(out, measure("H1b", "Signet, operator key, honest key pinned (operator-key)", "acceptance of A1 to A4",
		count(ToolSignet, "operator-key", "", all), ToolSignet, "other-key"))
	out = append(out, measure("H1c", "reproducible-trajectories, command criterion, adaptive attacker", "acceptance of A1 to A4",
		count(ToolRT, "command-criterion", "adaptive", all), "", ""))
	// H1d: the edit criterion on mutations of non-Write/Edit claims and on
	// A4; its detection of Write and Edit mutations is the edit split.
	edit := count(ToolRT, "edit-criterion", "adaptive", func(r SweepRow) bool {
		return r.Kind == "interval-widening" || !isEditMutation(r.Mutation)
	})
	out = append(out, measure("H1d", "reproducible-trajectories, edit criterion", "acceptance of mutations of non-Write/Edit claims and of A4", edit, "", ""))
	return out
}
