// Package agent isolates everything a harness does differently from the core
// verifier: how its session is read into a trajectory, how observed events are
// rewritten into comparable form, what the harness does on its own, and which
// content fields its format can state. Adding an agent means adding a package
// that implements Adapter and registers itself. pkg/matching and
// pkg/verification contain no agent knowledge.
package agent

import (
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// Adapter is the integration point for one agent harness.
type Adapter interface {
	// Name identifies the agent. A baseline capture is keyed on it.
	Name() string

	// Detect reports whether path is a session artifact this adapter reads, so
	// cmd/verify can choose an adapter without being told.
	Detect(path string) bool

	// Parse reads a session into trajectory entries in claim order. Order is
	// part of the output: the alignment depends on it. Each entry carries its
	// interval, its thread id where subagents were flattened, and its block id
	// where the format issued several calls at once. Report counts what was
	// skipped and why, and never drops silently.
	Parse(path string) (models.Trajectory, Report, error)

	// Normalize rewrites an observed event into the form claims use, for
	// example recovering the claimed command from the harness's wrapper argv.
	// It returns false to drop the event.
	Normalize(models.GroundTruthEvent) (models.GroundTruthEvent, bool)

	// IsHarnessNoise reports events the harness generates on the agent's
	// behalf that belong to neither the trajectory nor the agent's intent.
	// It is what the adapter knows statically. The measured baseline is
	// supplied separately.
	IsHarnessNoise(models.GroundTruthEvent) bool

	// Expresses reports whether the format can state a content field (one of
	// verification.Diff*) for this entry. A nil field is a finding only where
	// it can.
	Expresses(entry models.TrajectoryEntry, field string) bool

	// Process describes how claims map onto the process tree.
	Process() ProcessModel
}

// StreamNormalizer is implemented by an adapter whose observed events can only
// be put into comparable form by looking at several together: a harness that
// writes a file by creating a temporary, writing it and renaming it over the
// target produces five events for what the trajectory calls one write. It runs
// after Normalize, on events in time order with ties in arrival order.
type StreamNormalizer interface {
	NormalizeStream(models.GroundTruth) models.GroundTruth
}

// HarnessOwner is implemented by an adapter that can say which paths belong
// to the harness itself: its configuration, state and cache directories. The
// verifier reports an unexplained level-0 file event there as unexplained
// harness activity, which makes the run INCONCLUSIVE rather than NOT
// FAITHFUL (V-24). It is a declaration of where the harness keeps its own
// files, not of what it does there: nothing is explained by it, so a write
// there by the agent is still reported and still blocks FAITHFUL.
type HarnessOwner interface {
	IsHarnessOwned(path string) bool
}

// OpenCollapser is implemented by an adapter whose claims and NormalizeStream
// treat a run of opens of one file by one process as one access, broken only
// by another file event of that process (V-49). The verifier then folds such
// runs again once the baseline's and the harness's own events are set
// aside, since NormalizeStream, which runs before the baseline is known,
// let them break a run the claims join.
type OpenCollapser interface {
	CollapsesOpenRuns() bool
}

// BackgroundOutputter is implemented by an adapter that can name the files
// its harness writes a background command's output to and opens itself only
// while it writes them (I-73). An open of such a file after the last write
// the capture holds on it is then the agent's: the baseline does not explain
// it and it is not harness-owned activity (V-56).
type BackgroundOutputter interface {
	IsBackgroundOutput(path string) bool
}

// HarnessHoster is implemented by an adapter that can name the harness's own
// service hosts: exact host names, as the net probe reports a connection's
// target (its TLS SNI), that the harness itself connects to only sometimes,
// such as an access-token refresh. The verifier reports an unexplained
// level-0 net_connect to exactly one of them as unexplained harness network
// activity, which makes the run INCONCLUSIVE rather than NOT FAITHFUL (V-34).
// Like HarnessOwner it explains nothing: a connection there by a command the
// agent ran stays a finding, and no declared host is a baseline rule. Each
// host is declared from a measured capture (I-52, I-53).
type HarnessHoster interface {
	HarnessHosts() []string
}

// HarnessCommander is implemented by an adapter that can name the commands
// the harness itself starts only sometimes, such as Claude Code's probe for a
// package manager: each the exact command line of the exec the harness makes,
// as the proc probe reports it before the adapter's Normalize. The verifier
// reports a level-1 command whose own exec is one of them, that no baseline
// rule explains and no claim names, as an unexplained harness command, which
// makes the run INCONCLUSIVE rather than NOT FAITHFUL, and checks the events
// beneath it against what the controls' same command did (V-43). Like
// HarnessHoster it explains nothing and is no baseline rule. Each command is
// declared from measured captures.
type HarnessCommander interface {
	HarnessCommands() []string
}

// HarnessBookkeeper is implemented by an adapter that can name the exact
// files the harness itself rewrites as bookkeeping, in shapes or at times
// the control runs do not all show, such as Claude Code's version lock.
// Given the harness version the session records and the home the capture
// resolved "~/" against (empty when the capture does not say), it returns a
// predicate that recognises an event on one of those files with one of the
// event kinds the harness's own rewrite produces, or nil to declare nothing.
// The verifier explains a level-0 event it recognises, under the harness's
// own directories (HarnessOwner) and on a path no claim names, as declared
// harness bookkeeping: not a finding and no reason for INCONCLUSIVE (V-50).
// Unlike HarnessOwner this explains, so a declaration names exact files of
// one version, never a directory.
type HarnessBookkeeper interface {
	HarnessBookkeeping(version, home string) func(models.GroundTruthEvent) bool
}

// CaptureBookkeeper is implemented by an adapter that declares bookkeeping
// whose shape it can recognise only in the capture as the probe reported
// it, before NormalizeStream folded it (V-58): given the version, the home
// as for HarnessBookkeeper and the capture's raw events, it returns a
// predicate over the normalized events, or nil to declare nothing. A
// normalized event is recognised only by its own fields and raw events of
// the same process, so the join is exact.
type CaptureBookkeeper interface {
	CaptureBookkeeping(version, home string, raw models.GroundTruth) func(models.GroundTruthEvent) bool
}

// HarnessBookkeeping is the adapter's bookkeeping declaration for a capture
// and the harness version its session records (Report.AgentVersion), as
// the verifier takes it (verification.Options.HarnessBookkeeping, V-50):
// what HarnessBookkeeper declares and what CaptureBookkeeper declares for
// the capture's raw events (V-58). Nil when the adapter declares nothing or
// the session states no version: a declaration is keyed by the version,
// and a version from anywhere else (a configuration, a flag) is not the one
// the harness ran.
func HarnessBookkeeping(a Adapter, version string, g models.GroundTruthFile) func(models.GroundTruthEvent) bool {
	if version == "" {
		return nil
	}
	home := ""
	if g.Sensitive != nil {
		home = g.Sensitive.Home
	}
	var preds []func(models.GroundTruthEvent) bool
	if hb, ok := a.(HarnessBookkeeper); ok {
		if p := hb.HarnessBookkeeping(version, home); p != nil {
			preds = append(preds, p)
		}
	}
	if cb, ok := a.(CaptureBookkeeper); ok {
		if p := cb.CaptureBookkeeping(version, home, g.Events); p != nil {
			preds = append(preds, p)
		}
	}
	switch len(preds) {
	case 0:
		return nil
	case 1:
		return preds[0]
	}
	return func(e models.GroundTruthEvent) bool {
		for _, p := range preds {
			if p(e) {
				return true
			}
		}
		return false
	}
}

// Housekeeping is one network action the harness itself performs as
// housekeeping (V-54): a net_connect to Target, a host as the net probe
// writes a connection's target, or a net_request whose target is exactly
// Target, "<METHOD> <URL>" as the probe writes it, with a body when Body is
// true and with none when it is false. A connection has no body.
//
// With Origin, a request declaration covers every body-less request of one
// method to one origin (V-57): Target is "<METHOD> https://<host>/", and the
// declaration recognises a request without a body whose target starts with
// it, whatever its path and query, unless its path (the target after the
// host, up to a '?') is one of Except. Origin never covers a request with a
// body: an Origin declaration with Body, of a connection, or whose Target
// is not of that form declares nothing.
type Housekeeping struct {
	ActionType models.ActionType
	Target     string
	Body       bool
	Origin     bool
	Except     []string
}

// HarnessHousekeeper is implemented by an adapter that can name the exact
// network actions its harness performs on its own only sometimes, such as
// Claude Code's renewal of its login token. Given the harness version the
// session records, it returns them, or nothing for a version whose binary
// and captures were not read. The verifier explains a level-0 connection or
// request that one of them recognises, whose target no claim names, as
// declared harness housekeeping: not a finding and no reason for
// INCONCLUSIVE (V-54). Like HarnessBookkeeper this explains, so a
// declaration names exact targets of one version; only a body-less request
// may be declared for a whole origin (V-57).
type HarnessHousekeeper interface {
	HarnessHousekeeping(version string) []Housekeeping
}

// HarnessHousekeeping is the adapter's housekeeping declaration for the
// harness version its session records (Report.AgentVersion), as the
// verifier takes it (verification.Options.HarnessHousekeeping, V-54): a
// predicate that recognises a net_connect or net_request equal to a
// declared action, with an untruncated target and, for a request, a body
// exactly when the declaration says so, or a body-less request of a
// declared origin outside its excepted paths (V-57). Nil when the adapter
// declares nothing for the version or the session states none.
func HarnessHousekeeping(a Adapter, version string) func(models.GroundTruthEvent) bool {
	hk, ok := a.(HarnessHousekeeper)
	if !ok || version == "" {
		return nil
	}
	type key struct {
		t      models.ActionType
		target string
	}
	type origin struct {
		prefix string
		except map[string]bool
	}
	declared := map[key]bool{}
	var origins []origin
	for _, h := range hk.HarnessHousekeeping(version) {
		switch {
		case h.Target == "":
		case h.Origin:
			if h.ActionType == models.NetRequest && !h.Body && isOriginTarget(h.Target) {
				o := origin{prefix: h.Target, except: map[string]bool{}}
				for _, p := range h.Except {
					o.except[p] = true
				}
				origins = append(origins, o)
			}
		case h.ActionType == models.NetConnect && !h.Body:
			declared[key{h.ActionType, h.Target}] = false
		case h.ActionType == models.NetRequest:
			declared[key{h.ActionType, h.Target}] = h.Body
		}
	}
	if len(declared) == 0 && len(origins) == 0 {
		return nil
	}
	return func(e models.GroundTruthEvent) bool {
		if e.TargetTruncated {
			return false
		}
		if body, ok := declared[key{e.ActionType, e.Target}]; ok && (e.RequestHash != nil) == body {
			return true
		}
		if e.ActionType != models.NetRequest || e.RequestHash != nil {
			return false
		}
		for _, o := range origins {
			rest, ok := strings.CutPrefix(e.Target, o.prefix)
			if !ok {
				continue
			}
			path, _, _ := strings.Cut("/"+rest, "?")
			if !o.except[path] {
				return true
			}
		}
		return false
	}
}

// isOriginTarget reports whether target has the form of an origin
// declaration, "<METHOD> https://<host>/": a method of capital letters, the
// https scheme, a host with no slash, query, fragment, user information or
// space, and the root path (V-57).
func isOriginTarget(target string) bool {
	method, url, ok := strings.Cut(target, " ")
	if !ok || method == "" || strings.Trim(method, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return false
	}
	host, ok := strings.CutPrefix(url, "https://")
	if !ok {
		return false
	}
	host, ok = strings.CutSuffix(host, "/")
	return ok && host != "" && !strings.ContainsAny(host, "/?#@ ")
}

// HarnessCommand recognises, among a capture's normalized events, the execs
// of the adapter's declared harness commands (V-43): an exec whose raw
// target, before Normalize, is exactly a declared command line, not
// truncated, and which Normalize left unchanged. The raw event is matched by
// its pid and timestamp, which Normalize keeps, so an exec Normalize rewrote
// into a declared command line (an agent's shell call whose payload is that
// text) is never recognised. Nil when the adapter declares nothing or no exec
// of the capture is a declared one.
func HarnessCommand(a Adapter, raw models.GroundTruth) func(models.GroundTruthEvent) bool {
	hc, ok := a.(HarnessCommander)
	if !ok {
		return nil
	}
	declared := map[string]bool{}
	for _, c := range hc.HarnessCommands() {
		if c != "" {
			declared[c] = true
		}
	}
	type key struct {
		pid uint32
		ts  int64
	}
	execs := map[key]string{}
	for _, e := range raw {
		if e.ActionType == models.ProcessExec && !e.TargetTruncated && declared[e.Target] {
			execs[key{e.PID, e.Timestamp.UnixNano()}] = e.Target
		}
	}
	if len(execs) == 0 {
		return nil
	}
	return func(e models.GroundTruthEvent) bool {
		t, ok := execs[key{e.PID, e.Timestamp.UnixNano()}]
		return ok && e.ActionType == models.ProcessExec && !e.TargetTruncated && e.Target == t
	}
}

// SensitiveDeclarer is implemented by an adapter that can name the harness's
// security-sensitive files: the short list of its settings, permission and
// configuration files whose change by the agent would change what the
// harness lets the agent do. cmd/watch snapshots them at the start and the
// stop of a capture, and the verifier checks what changed against what the
// control runs changed (V-40). Each entry starts with "~/" (the home of the
// user the agent runs as) or "{workspace}/" (the watched directory). Each
// is declared from a measured capture or the harness's own documentation
// (I-59).
type SensitiveDeclarer interface {
	SensitiveFiles() []string
}

// SensitiveFiles is the adapter's declared sensitive files, or nil.
func SensitiveFiles(a Adapter) []string {
	if d, ok := a.(SensitiveDeclarer); ok {
		return d.SensitiveFiles()
	}
	return nil
}

// SensitiveKeyDeclarer is implemented by an adapter one of whose declared
// sensitive files mixes the harness's state (caches, counters, timestamps)
// with its settings. SensitiveKeys returns, for such a file as it is
// declared, the key paths that decide what the harness lets the agent do:
// patterns of dot-separated elements, "*" matching any one element (a
// per-project entry keyed by its directory, say). An unexplained change
// under one of them is a finding; any other unexplained change of the file
// is listed report-only (V-41). Nil for a file that is settings only, whose
// every key path is checked. Each pattern is declared from the harness's
// binary and documentation (I-60).
type SensitiveKeyDeclarer interface {
	SensitiveKeys(file string) []string
}

// SensitiveKeys is the adapter's security-relevant key paths of a declared
// sensitive file, or nil when every key path of it is checked.
func SensitiveKeys(a Adapter, file string) []string {
	if d, ok := a.(SensitiveKeyDeclarer); ok {
		return d.SensitiveKeys(file)
	}
	return nil
}

// Canonicalizer is implemented by an adapter whose observed targets carry ids
// that differ every run: a session id, a pid, a task id in the harness's own
// file paths. Canonical returns the event with those ids replaced by fixed
// tokens. It is applied only where events of different runs are compared:
// when Capture builds rules from control runs and when Prepare matches a
// run's events against them. Pairing a claim with an event, and every other
// comparison within one run, uses the exact target, so a claim names one
// file, not a family of them (I-41).
type Canonicalizer interface {
	Canonical(models.GroundTruthEvent) models.GroundTruthEvent
}

// canonical is the event as it is compared with other runs.
func canonical(a Adapter, e models.GroundTruthEvent) models.GroundTruthEvent {
	if c, ok := a.(Canonicalizer); ok {
		return c.Canonical(e)
	}
	return e
}

// IntervalKind says what an entry's start timestamp means.
type IntervalKind int

const (
	// IntervalNone: the format reports a point, not an interval.
	IntervalNone IntervalKind = iota
	// IntervalDecision: the start is when the agent decided, and may include
	// approval or queueing latency (Claude Code's tool_use).
	IntervalDecision
	// IntervalExecution: the start is when execution began (Gemini's started).
	IntervalExecution
)

func (k IntervalKind) String() string {
	switch k {
	case IntervalDecision:
		return "decision"
	case IntervalExecution:
		return "execution"
	default:
		return "none"
	}
}

// Concurrency says whether the claim sequence is totally ordered.
type Concurrency int

const (
	// Sequential: one call at a time, so claim order is total.
	Sequential Concurrency = iota
	// Parallel: the harness can issue several calls at once, so entries that
	// share a BlockID have no order among themselves.
	Parallel
	// ConcurrencyUnmeasured: not yet measured for this agent.
	ConcurrencyUnmeasured
)

// ProcessModel describes how an agent's claims map onto the process tree.
type ProcessModel struct {
	// ShellPerCommand: each shell claim execs its own process, so claims align
	// at level 1. False means a persistent shell: no level-1 subtree, and both
	// checks lose their subject.
	ShellPerCommand bool
	// SubagentsInProcess: subagent actions are indistinguishable from
	// main-thread ones in the ground truth, which forces flattening.
	SubagentsInProcess bool
	// Containerized: observed paths and pids live in another namespace from the
	// trajectory's. Not handled by any adapter yet.
	Containerized bool
	// IntervalKind says what the start timestamp means.
	IntervalKind IntervalKind
	// Concurrency says whether the claim sequence is totally ordered.
	Concurrency Concurrency
	// ExitsClaimed is true when the format records process exits, so exits are
	// aligned. False makes the verifier ignore exits on both sides.
	ExitsClaimed bool
}

// Report makes what was not measured visible.
type Report struct {
	// ToolCalls is how many tool invocations the session held.
	ToolCalls int
	// Entries is how many trajectory entries they produced.
	Entries int
	// UnmappedByTool counts tool calls that produced no entry, by tool name.
	// Non-effectful tools are expected here. A tool that is neither mapped nor
	// known to be non-effectful is listed in UnknownTools as well.
	UnmappedByTool map[string]int
	// UnknownTools are tools the adapter has no mapping for and has not
	// declared non-effectful. They may be actions the verifier cannot see.
	UnknownTools []string
	// ParseErrors lists records that could not be read.
	ParseErrors []string
	// Degradations names every precision loss the core must report: a
	// decision-time start, no exit codes, a persistent shell, no baseline.
	Degradations []string
	// AgentVersion is the harness version the session records, when the
	// format states one. A baseline holds for one version, so cmd/verify
	// refuses a baseline captured for another.
	AgentVersion string
	// ServerCalls are the calls the session records that the harness's model
	// API ran on its own side, such as Claude Code's WebSearch, with the
	// request id the session gives each. They produce no entry and are
	// counted in UnmappedByTool as well; a caller passes them to the
	// verifier as Input.ServerCalls, which joins them to the capture's
	// responses (V-45).
	ServerCalls []verification.ServerCall `json:"server_calls,omitempty"`
	// ModelRequests are the requests the record says the harness sent to
	// its model API, each with its input items digested as the net probe
	// digests a captured request (tlsparse.ResponsesItemDigest), and
	// ModelRequestMethod the content method that carries them; a caller
	// passes them to the verifier as Input.ModelRequests and
	// Input.ModelRequestMethod (P-43).
	ModelRequests      []verification.ModelRequest `json:"model_requests,omitempty"`
	ModelRequestMethod string                      `json:"model_request_method,omitempty"`
}

// Count records a tool call that produced no entry.
func (r *Report) Count(tool string) {
	if r.UnmappedByTool == nil {
		r.UnmappedByTool = map[string]int{}
	}
	r.UnmappedByTool[tool]++
}

// NormalizeGround puts observed events into the form claims use: every event
// through the adapter's Normalize, dropping those it rejects, then the whole
// stream through NormalizeStream when the adapter has one. Prepare and the
// baseline's Capture both use it, so a rule is measured on the same shape the
// verifier compares against; a baseline normalized by only one of the two
// steps named the raw temporaries of every atomic write and explained none of
// them.
func NormalizeGround(a Adapter, events models.GroundTruth) models.GroundTruth {
	ground := make(models.GroundTruth, 0, len(events))
	for _, e := range events {
		if n, keep := a.Normalize(e); keep {
			ground = append(ground, n)
		}
	}
	if sn, ok := a.(StreamNormalizer); ok {
		ground = sn.NormalizeStream(ground)
	}
	return ground
}

// ContentClaimer is implemented by an adapter some of whose claims only a
// capture that read the agent's request content can witness, such as Claude
// Code's WebFetch request (I-72). Without that content the probe emits no
// request at all, so such a claim would be Unwitnessed for the capture's
// limit, not the agent's; Prepare drops it, and the adapter keeps a claim the
// capture can check, the connection, beside it.
type ContentClaimer interface {
	NeedsContent(models.TrajectoryEntry) bool
}

// ContentMethodDeclarer is implemented by an adapter whose content claims
// depend on one content method of the net probe (N-42): ContentMethod names
// it for a claim, such as tls-rustls-aead for Codex's model traffic, or ""
// for the probe's state as a whole. An adapter without it reads the whole,
// which for a single-method capture is that method's.
type ContentMethodDeclarer interface {
	ContentMethod(models.TrajectoryEntry) string
}

// contentRead reports whether the capture read the request content a claim
// depends on: the state of the content method the adapter declares for it,
// else the net probe's content capture as a whole (N-16, N-42).
func contentRead(a Adapter, c *models.Coverage, e models.TrajectoryEntry) bool {
	if c == nil {
		return false
	}
	net := c.Probes["net"]
	if d, ok := a.(ContentMethodDeclarer); ok {
		if m := d.ContentMethod(e); m != "" {
			req, _ := net.MethodContent(m)
			return req == models.ContentActive
		}
	}
	return net.Content == models.ContentActive
}

// Prepare turns a capture and an adapter into verification input: observed
// events are normalized, the adapter's noise filter and the measured baseline
// are combined into one baseline, and the adapter's field declarations and
// exit handling become options. measured may be nil. The capture is rooted
// at the harness process when the adapter declares a launcher (Rooted,
// I-81). The measured baseline
// was built from other runs, so it sees each event in its canonical form; the
// events the verifier pairs keep their exact targets (I-41).
func Prepare(a Adapter, claims models.Trajectory, g models.GroundTruthFile, measured verification.Baseline, opts verification.Options) verification.Input {
	g = Rooted(a, g)
	if cc, ok := a.(ContentClaimer); ok {
		kept := make(models.Trajectory, 0, len(claims))
		for _, c := range claims {
			if !cc.NeedsContent(c) || contentRead(a, g.Coverage, c) {
				kept = append(kept, c)
			}
		}
		claims = kept
	}
	ground := NormalizeGround(a, g.Events)
	baseline := func(e models.GroundTruthEvent) bool {
		return a.IsHarnessNoise(e) || (measured != nil && measured(canonical(a, e)))
	}
	opts.Expresses = a.Expresses
	opts.IgnoreExits = !a.Process().ExitsClaimed
	if ho, ok := a.(HarnessOwner); ok {
		opts.HarnessOwned = ho.IsHarnessOwned
	}
	if hh, ok := a.(HarnessHoster); ok {
		opts.HarnessHosts = hh.HarnessHosts()
	}
	if oc, ok := a.(OpenCollapser); ok {
		opts.CollapseOpenRuns = oc.CollapsesOpenRuns()
	}
	if bo, ok := a.(BackgroundOutputter); ok {
		opts.BackgroundOutput = bo.IsBackgroundOutput
	}
	opts.HarnessCommand = HarnessCommand(a, g.Events)
	return verification.Input{
		Claims:    claims,
		Ground:    ground,
		RootPID:   g.RootPID,
		Coverage:  g.Coverage,
		Baseline:  baseline,
		FSScope:   g.FSScope,
		Workspace: g.Workspace,
		Sensitive: SensitiveInput(a, g, nil),
		Options:   opts,
	}
}

// BaselineSubtree is the baseline's subtree records for a run, in the form
// the verifier asks about them (verification.Input.BaselineSubtree, V-38):
// the command and the event beneath it are compared in their canonical form,
// as rules are. A command the adapter declares harness noise explains its
// whole subtree, as before. Nil when there is no baseline or it records no
// subtrees, which keeps the V7 reading.
func BaselineSubtree(a Adapter, b *Baseline, workspace string) verification.SubtreeBaseline {
	if b == nil {
		return nil
	}
	sub := b.Subtree(workspace)
	if sub == nil {
		return nil
	}
	return func(command, e models.GroundTruthEvent) bool {
		return a.IsHarnessNoise(command) || sub(canonical(a, command), canonical(a, e))
	}
}

// PrepareWithBaseline is Prepare with a measured baseline: its rules as the
// predicate and its subtree records as Input.BaselineSubtree (V-38). b may be
// nil. Prepare given only b.Predicate leaves every baselined command
// explaining its whole subtree, so a caller that holds a Baseline uses this.
func PrepareWithBaseline(a Adapter, claims models.Trajectory, g models.GroundTruthFile, b *Baseline, opts verification.Options) verification.Input {
	var measured verification.Baseline
	if b != nil {
		measured = b.Predicate(g.Workspace)
	}
	in := Prepare(a, claims, g, measured, opts)
	in.BaselineSubtree = BaselineSubtree(a, b, g.Workspace)
	in.Sensitive = SensitiveInput(a, g, b)
	return in
}

// SensitiveInput is the capture's snapshot of the adapter's declared
// sensitive files with the baseline's record of them and the adapter's
// security-relevant key paths of each, as the verifier checks it (V-40,
// V-41). Nil when the capture holds no snapshot or the adapter
// declares no file, which checks and reports nothing. b may be nil, or hold
// no record: the changes are then reported as not checked.
func SensitiveInput(a Adapter, g models.GroundTruthFile, b *Baseline) *verification.SensitiveInput {
	declared := SensitiveFiles(a)
	if g.Sensitive == nil || len(declared) == 0 {
		return nil
	}
	in := &verification.SensitiveInput{}
	var baselined map[string]bool
	if b != nil && b.Sensitive != nil {
		in.Explained = b.SensitiveExplained(g.Workspace)
		baselined = map[string]bool{}
		for _, f := range b.Sensitive.Files {
			baselined[f] = true
		}
	}
	for _, d := range declared {
		sf := verification.SensitiveFile{File: d, Baselined: baselined[d], Keys: SensitiveKeys(a, d)}
		if f := snapshotFile(g.Sensitive, d); f != nil {
			sf.Path, sf.Recorded, sf.Start, sf.Stop = f.Path, true, f.Start.State, f.Stop.State
			for _, c := range f.Changes {
				sf.Changes = append(sf.Changes, verification.SensitiveChange{File: d, Path: f.Path, SensitiveChange: c})
			}
		}
		in.Files = append(in.Files, sf)
	}
	return in
}
