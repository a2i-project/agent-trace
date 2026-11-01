package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/attack"
	"github.com/agent-trace/agent-trace/pkg/config"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// Session is one run loaded for verification: the adapter's claims, the
// capture, and the control runs the baseline is built from.
type Session struct {
	Rec         RunRecord
	ID          string
	Dir         string
	ControlsDir string
	Adapter     agent.Adapter
	Claims      models.Trajectory
	Report      agent.Report
	G           models.GroundTruthFile
	// Controls are the usable control runs; ControlsDropped counts those left
	// out because they lost events or did not parse (X2).
	Controls        []models.GroundTruthFile
	ControlsDropped int
	DroppedReasons  []string
	// ControlTools is the control task's tool set as the capture script
	// recorded it (control-tools.txt), "" when it did not.
	ControlTools string
	// Version is the version the baseline and the strict check use: the one
	// the session states, else the manifest's.
	Version string
	// Trace is what reading the session found (V-59): a session that is
	// missing, empty or damaged is a result, never a load error.
	Trace verification.TraceInput
}

// controlFile matches control-N.ground_truth.json.
var controlFile = regexp.MustCompile(`^control-(\d+)\.ground_truth\.json$`)

// ControlPaths lists a directory's control captures in numeric order.
func ControlPaths(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type numbered struct {
		n    int
		path string
	}
	var found []numbered
	for _, e := range entries {
		if m := controlFile.FindStringSubmatch(e.Name()); m != nil {
			n, _ := strconv.Atoi(m[1])
			found = append(found, numbered{n, filepath.Join(dir, e.Name())})
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].n < found[j].n })
	out := make([]string, len(found))
	for i, f := range found {
		out[i] = f.path
	}
	return out
}

// LoadControls reads control captures, keeping those a baseline may use: a
// control with no coverage record or with any loss would leave the baseline
// short (X2, and cmd/baseline refuses it).
func LoadControls(paths []string) (kept []models.GroundTruthFile, dropped []string) {
	for _, p := range paths {
		f, err := readGroundTruth(p)
		if err != nil {
			dropped = append(dropped, fmt.Sprintf("%s: %v", filepath.Base(p), err))
			continue
		}
		if f.Coverage == nil {
			dropped = append(dropped, filepath.Base(p)+": no coverage record")
			continue
		}
		if c := verification.Assess(f.Coverage); !c.Complete {
			dropped = append(dropped, filepath.Base(p)+": "+strings.Join(c.Reasons, "; "))
			continue
		}
		kept = append(kept, f)
	}
	return kept, dropped
}

func readGroundTruth(path string) (models.GroundTruthFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return models.GroundTruthFile{}, err
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		return models.GroundTruthFile{}, fmt.Errorf("parse: %w", err)
	}
	return f, nil
}

// trajectoryName is the session file's name in a run directory: the one the
// manifest names, else the one the agent's profile gives (trace.file), from
// the campaign's config or, when it has none, the default one.
func trajectoryName(c *Campaign, r RunRecord) (string, error) {
	if p := r.Paths["trajectory"]; p != nil && *p != "" {
		return filepath.Base(*p), nil
	}
	cfg := c.Config
	if cfg == nil {
		var err error
		if cfg, err = config.LoadDefault(""); err != nil {
			return "", fmt.Errorf("the manifest names no trajectory of the run, and no agent profile can: %w", err)
		}
	}
	name, ok := cfg.TraceFile(r.Agent, r.Task)
	if !ok {
		return "", fmt.Errorf("the manifest names no trajectory of the run, and %s gives the %s profile no trace.file", cfg.Path, r.Agent)
	}
	return name, nil
}

func groundTruthName(r RunRecord) string {
	if p := r.Paths["ground_truth"]; p != nil && *p != "" {
		return filepath.Base(*p)
	}
	return r.Task + ".ground_truth.json"
}

// LoadSession reads a run's session, capture and controls. For an adapter
// that declares its trace (I-74), a session that is missing, empty or does
// not parse is a trace that cannot be verified, kept in s.Trace and
// verified as such (V-59), never a load error; for another adapter, and for
// the capture, a file that is missing or does not parse is an error the
// caller records as X4.
func LoadSession(c *Campaign, r RunRecord) (*Session, error) {
	s := &Session{Rec: r, ID: c.ID(r), Dir: c.RunDir(r), ControlsDir: c.ControlsDir(r)}
	a, ok := agent.Lookup(r.Agent)
	if !ok {
		return s, fmt.Errorf("no adapter %q is registered", r.Agent)
	}
	s.Adapter = a
	name, err := trajectoryName(c, r)
	if err != nil {
		return s, err
	}
	claims, rep, trace, err := agent.ReadTrace(a, filepath.Join(s.Dir, name), false)
	if err != nil {
		return s, fmt.Errorf("read the session: %w", err)
	}
	if len(rep.ParseErrors) != 0 {
		return s, fmt.Errorf("the session has %d record(s) that did not parse: %s", len(rep.ParseErrors), rep.ParseErrors[0])
	}
	s.Claims, s.Report, s.Trace = claims, rep, trace
	if s.G, err = readGroundTruth(filepath.Join(s.Dir, groundTruthName(r))); err != nil {
		return s, fmt.Errorf("read the capture: %w", err)
	}
	paths := ControlPaths(s.ControlsDir)
	s.Controls, s.DroppedReasons = LoadControls(paths)
	s.ControlsDropped = len(s.DroppedReasons)
	if b, err := os.ReadFile(filepath.Join(s.ControlsDir, "control-tools.txt")); err == nil {
		s.ControlTools = strings.TrimSpace(string(b))
	}
	s.Version = rep.AgentVersion
	if s.Version == "" {
		s.Version = r.Version
	}
	return s, nil
}

// Facts gathers what the exclusion rules read.
func (s *Session) Facts(ann Annotation, loadErr error) RunFacts {
	f := RunFacts{Status: s.Rec.Status, ManifestVersion: s.Rec.Version, VersionAfter: s.Rec.VersionAfter, Recorded: s.Rec.Exclusion, Annotation: ann, Claims: len(s.Claims)}
	if loadErr != nil {
		f.ParseError = loadErr.Error()
		return f
	}
	f.SessionVersion = s.Report.AgentVersion
	f.LossReasons = lossReasons(s.G.Coverage)
	return f
}

// lossReasons are the completeness reasons of a capture that state lost
// events (X1, the loss cause of H3c). An incomplete capture for another
// reason, io_uring socket operations (N-25), is not loss: the protocol counts
// it under its own cause and keeps the run.
func lossReasons(cov *models.Coverage) []string {
	if cov == nil {
		return []string{"no coverage record"}
	}
	var out []string
	for _, r := range verification.Assess(cov).Reasons {
		for _, h := range ClassifyReason(r) {
			if h.Cause == CauseEventLoss {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// versionReason is cmd/verify's --strict-version check (I-57) for one
// session: why the run is INCONCLUSIVE for its version, or "".
func versionReason(cfg *config.Config, adapter, version string) string {
	const note = "(--strict-version, I-57)"
	// The config is named by its file name: its full path is the analysing
	// machine's, and results.json is meant to be published (D14).
	name := filepath.Base(cfg.Path)
	switch {
	case !cfg.Has(adapter):
		return fmt.Sprintf("%s has no entry for the %s adapter, so no version of it is verified %s", name, adapter, note)
	case version == "":
		return fmt.Sprintf("the session does not state the %s version and --agent-version was not given, so it cannot be checked against %s %s", adapter, name, note)
	case !cfg.Configured(adapter, version):
		return fmt.Sprintf("the session was recorded by %s version %s, which %s does not configure (configured: %s): the adapter was verified on those versions only %s", adapter, version, name, strings.Join(cfg.Versions(adapter), ", "), note)
	}
	return ""
}

// applyStrict makes the verdict INCONCLUSIVE when the version is not
// configured, as verify --strict-version does; findings stay listed.
func applyStrict(v verification.Verdict, reason string) verification.Verdict {
	if reason == "" {
		return v
	}
	if n := v.Findings(); n > 0 {
		reason += fmt.Sprintf("; the %d finding(s) above may come from that", n)
	}
	v.Outcome = verification.OutcomeInconclusive
	v.Faithful = false
	v.Reasons = append([]string{reason}, v.Reasons...)
	return v
}

// BuildBaseline builds a baseline from control runs the way the capture
// script does: at the given agreement, with the control task's own command
// (I-28) and its edited file (I-88) excluded; the file is excluded for
// every agent, since controls that edit nothing never name it. The capture
// time is fixed so the baseline is a function of its inputs.
func BuildBaseline(a agent.Adapter, version string, controls []models.GroundTruthFile, agreement float64) (*agent.Baseline, error) {
	b, err := agent.Capture(a, version, controls, time.Unix(0, 0).UTC(), agent.CaptureOptions{MinAgreement: agreement, Exclude: []string{agent.ControlCommand, agent.ControlFileTarget}})
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// input prepares verification input for claims against this session's capture.
func (s *Session) input(claims models.Trajectory, b *agent.Baseline) verification.Input {
	in := agent.PrepareWithBaseline(s.Adapter, claims, s.G, b, verification.Options{IntervalSlack: IntervalSlack})
	// The session's own version, as cmd/verify takes it (V-50).
	in.Options.HarnessBookkeeping = agent.HarnessBookkeeping(s.Adapter, s.Report.AgentVersion, s.G)
	in.Options.HarnessHousekeeping = agent.HarnessHousekeeping(s.Adapter, s.Report.AgentVersion) // V-54
	in.Trace = s.Trace
	in.Trace.Decl = agent.Trace(s.Adapter, s.G) // V-59
	return in
}

func (s *Session) verify(claims models.Trajectory, b *agent.Baseline) verification.Verdict {
	return verification.Verify(s.input(claims, b))
}

// observed is every target the capture observed after normalization, raw,
// plus every claim's target, so a generated claim cannot be true by accident
// (cmd/attack --avoid-ground-truth).
func (s *Session) observed() map[string]bool {
	avoid := map[string]bool{}
	in := agent.Prepare(s.Adapter, s.Claims, s.G, nil, verification.Options{})
	for _, e := range in.Ground {
		avoid[e.Target] = true
	}
	for _, e := range s.G.Events {
		avoid[e.Target] = true
	}
	for _, e := range s.Claims {
		avoid[e.Target] = true
	}
	return avoid
}

// RestingPaths counts the level-0 paths a baseline holds: reads (file_open
// rules, V-36) and distinct write-class paths (V-37), as cmd/verify reports
// them.
func RestingPaths(b *agent.Baseline, workspace string) (reads, writes int) {
	if b == nil {
		return 0, 0
	}
	seen := map[string]bool{}
	for _, r := range b.Rules {
		if len(workspace) < 2 && (strings.Contains(r.Target, agent.WorkspacePlaceholder) || strings.Contains(r.Target, agent.MangledWorkspacePlaceholder)) {
			continue
		}
		switch r.ActionType {
		case models.FileOpen:
			reads++
		case models.FileWrite, models.FileClose, models.FileRename, models.FileDelete:
			if !seen[r.Target] {
				seen[r.Target] = true
				writes++
			}
		}
	}
	return reads, writes
}

// claimKey identifies a claim by what the scorer matches on.
func claimKey(e models.TrajectoryEntry) string {
	return fmt.Sprintf("%s|%s|%s|%d", e.ActionType, e.Target, e.Tool, e.Timestamp.UnixNano())
}

// H3Run is one honest run's verdict, reduced to what H3 reads.
type H3Run struct {
	Outcome string `json:"outcome"`
	// Findings is Verdict.Findings(); FlaggedClaims the distinct claims
	// flagged Mismatched, Unwitnessed or OutsideInterval, of Claims, the
	// agent's own claims (harness-implied ones, ImpliedClaims, excluded).
	Findings      int `json:"findings"`
	FlaggedClaims int `json:"flagged_claims"`
	Claims        int `json:"claims"`
	ImpliedClaims int `json:"implied_claims"`
	// The per-run counts reported beside the per-claim rate: not claims.
	Unrecorded           int  `json:"unrecorded"`
	UnexplainedSubtrees  int  `json:"unexplained_subtrees"`
	UnexplainedSensitive int  `json:"unexplained_sensitive_changes"`
	Ambiguous            bool `json:"ambiguous"`
	// TraceState is the state of a trace that could not be read whole and
	// TraceTampering the evidence that it was tampered with (V-59); both
	// absent for an intact trace no process but the harness changed.
	TraceState     string `json:"trace_state,omitempty"`
	TraceTampering int    `json:"trace_tampering,omitempty"`
	// HarnessShared counts corroborated reads shared with the harness (V-36).
	HarnessShared int      `json:"harness_shared_reads"`
	Reasons       []string `json:"reasons,omitempty"`
	// Attribution is set for an INCONCLUSIVE run, and for a loss run whatever
	// its outcome (X1 counts under the loss cause).
	Attribution *Attribution `json:"attribution,omitempty"`
	// RestingReads and RestingWrites are the baseline's level-0 paths.
	RestingReads  int `json:"baseline_resting_reads"`
	RestingWrites int `json:"baseline_resting_writes"`
	Controls      int `json:"controls_used"`
	// Error is set when no verdict could be computed (no usable control).
	Error string `json:"error,omitempty"`
}

// Faithful and Inconclusive read the outcome.
func (h H3Run) Faithful() bool     { return h.Outcome == verification.OutcomeFaithful.String() }
func (h H3Run) Inconclusive() bool { return h.Outcome == verification.OutcomeInconclusive.String() }

// SummarizeVerdict reduces a verdict to an H3Run. loss says the run is an X1
// run, which is attributed whatever its outcome.
func SummarizeVerdict(v verification.Verdict, claims models.Trajectory, loss bool) H3Run {
	h := H3Run{
		Outcome: v.Outcome.String(), Findings: v.Findings(), Unrecorded: len(v.Unrecorded),
		UnexplainedSubtrees: len(v.Coverage.UnexplainedSubtrees), UnexplainedSensitive: len(v.UnexplainedSensitiveChanges),
		Ambiguous: v.Ambiguous, HarnessShared: len(v.CorroboratedHarnessShared), Reasons: v.Reasons,
		TraceState: string(v.Trace.State), TraceTampering: len(v.TraceTampering),
	}
	for _, c := range claims {
		if c.ImpliedBy != "" {
			h.ImpliedClaims++
		} else {
			h.Claims++
		}
	}
	flagged := map[string]bool{}
	for _, p := range v.Mismatched {
		flagged[claimKey(p.Entry)] = true
	}
	for _, p := range v.OutsideInterval {
		flagged[claimKey(p.Entry)] = true
	}
	for _, e := range v.Unwitnessed {
		flagged[claimKey(e)] = true
	}
	h.FlaggedClaims = len(flagged)
	if h.Inconclusive() || loss {
		reasons := v.Reasons
		if len(reasons) == 0 {
			reasons = v.Completeness.Reasons
		}
		a := Attribute(reasons)
		h.Attribution = &a
	}
	return h
}

// Honest verifies the unmodified claims through the adapter path with the
// given baseline and strict reason, and summarizes the verdict.
func (s *Session) Honest(b *agent.Baseline, strict string, loss bool) *H3Run {
	v := applyStrict(s.verify(s.Claims, b), strict)
	h := SummarizeVerdict(v, s.Claims, loss)
	h.RestingReads, h.RestingWrites = RestingPaths(b, s.G.Workspace)
	if b != nil {
		h.Controls = b.Runs
	}
	return &h
}

// Surface is the attack surface (protocol 5.6) of one session at one baseline
// setting (protocol 5.6): how many single omissions are undetectable by
// design.
type Surface struct {
	Claims                int      `json:"claims"`
	Undetectable          int      `json:"undetectable_single_omissions"`
	UndetectableFraction  *float64 `json:"undetectable_fraction"`
	SensitiveSelected     int      `json:"sensitive_selected"`
	SensitiveUndetectable int      `json:"sensitive_selected_undetectable"`
	RestingReads          int      `json:"baseline_resting_reads"`
	RestingWrites         int      `json:"baseline_resting_writes"`
}

// SurfaceOf computes the attack surface from the honest run through the
// attack path: the claims without the harness-implied ones, which the
// generators refuse.
func (s *Session) SurfaceOf(b *agent.Baseline) (Surface, verification.Verdict, verification.Baseline) {
	claims, _ := attack.WithoutImplied(s.Claims)
	// The honest run as the sweep reads it: with the harness-implied claims.
	in := s.input(attack.WithImplied(s.Claims, claims, attack.Record{}), b)
	honest := verification.Verify(in)
	res := attack.Result{Kind: attack.Omission}
	for i := range claims {
		res.Mutations = append(res.Mutations, attack.MutationResult{Mutation: attack.Mutation{Kind: attack.Omission, OriginalIndex: i, Index: -1, Before: &claims[i]}})
	}
	res = attack.MarkUndetectableByDesign(res, honest, in.BaselineInEffect())
	sf := Surface{Claims: len(claims)}
	for i, m := range res.Mutations {
		sens := attack.Sensitive(claims[i])
		if sens {
			sf.SensitiveSelected++
		}
		if m.UndetectableByDesign {
			sf.Undetectable++
			if sens {
				sf.SensitiveUndetectable++
			}
		}
	}
	sf.UndetectableFraction = ratioPtr(sf.Undetectable, sf.Claims)
	sf.RestingReads, sf.RestingWrites = RestingPaths(b, s.G.Workspace)
	return sf, honest, in.BaselineInEffect()
}

// Difference is one way the attack path and the adapter path read the honest
// run differently (premise check, protocol 5.2).
type Difference struct {
	What        string `json:"what"`
	AttackPath  string `json:"attack_path"`
	AdapterPath string `json:"adapter_path"`
}

// findingKeys lists a verdict's findings as stable strings.
func findingKeys(v verification.Verdict, claims models.Trajectory) []string {
	d := attack.Diagnose(attack.Record{}, attack.Result{}, v, claims)
	var keys []string
	for _, f := range d.Findings {
		keys = append(keys, findingKey(f))
	}
	for _, c := range v.UnexplainedSensitiveChanges {
		keys = append(keys, fmt.Sprintf("unexplained_sensitive|%v", c))
	}
	sort.Strings(keys)
	return keys
}

// CompareHonest lists every difference between the honest verdict through the
// attack path and through the adapter path: the outcome, the size of each
// list, and each finding present on only one side.
func CompareHonest(attackClaims models.Trajectory, attackV verification.Verdict, adapterClaims models.Trajectory, adapterV verification.Verdict) []Difference {
	var out []Difference
	add := func(what string, a, b any) {
		if sa, sb := fmt.Sprint(a), fmt.Sprint(b); sa != sb {
			out = append(out, Difference{What: what, AttackPath: sa, AdapterPath: sb})
		}
	}
	add("outcome", attackV.Outcome, adapterV.Outcome)
	add("claims", len(attackClaims), len(adapterClaims))
	add("corroborated", len(attackV.Corroborated), len(adapterV.Corroborated))
	add("mismatched", len(attackV.Mismatched), len(adapterV.Mismatched))
	add("unwitnessed", len(attackV.Unwitnessed), len(adapterV.Unwitnessed))
	add("unrecorded", len(attackV.Unrecorded), len(adapterV.Unrecorded))
	add("outside_interval", len(attackV.OutsideInterval), len(adapterV.OutsideInterval))
	add("unexplained_subtrees", len(attackV.Coverage.UnexplainedSubtrees), len(adapterV.Coverage.UnexplainedSubtrees))
	add("unverified", len(attackV.Unverified), len(adapterV.Unverified))
	add("out_of_scope", len(attackV.OutOfScope), len(adapterV.OutOfScope))
	add("out_of_capture", len(attackV.OutOfCapture), len(adapterV.OutOfCapture))
	add("unexplained_harness", len(attackV.UnexplainedHarness), len(adapterV.UnexplainedHarness))
	add("unexplained_harness_net", len(attackV.UnexplainedHarnessNet), len(adapterV.UnexplainedHarnessNet))
	add("outside_writes", len(attackV.OutsideWrites), len(adapterV.OutsideWrites))
	add("harness_implied", len(attackV.HarnessImplied), len(adapterV.HarnessImplied))
	add("ambiguous", attackV.Ambiguous, adapterV.Ambiguous)
	ak, bk := findingKeys(attackV, attackClaims), findingKeys(adapterV, adapterClaims)
	inB := map[string]bool{}
	for _, k := range bk {
		inB[k] = true
	}
	inA := map[string]bool{}
	for _, k := range ak {
		inA[k] = true
		if !inB[k] {
			out = append(out, Difference{What: "finding", AttackPath: k, AdapterPath: "absent"})
		}
	}
	for _, k := range bk {
		if !inA[k] {
			out = append(out, Difference{What: "finding", AttackPath: "absent", AdapterPath: k})
		}
	}
	return out
}
