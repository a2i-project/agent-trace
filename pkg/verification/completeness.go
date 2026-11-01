package verification

import (
	"fmt"
	"sort"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Completeness is the verifier's judgement of whether the ground truth can
// support a FAITHFUL verdict. See docs/decisions/verification.md, V-13 to V-15.
type Completeness struct {
	// Complete is true only when a coverage record exists and shows no event
	// loss on any probe that ran.
	Complete bool
	// Reasons lists why Complete is false. Empty when Complete is true.
	Reasons []string
	// Notes lists content-level gaps that do not make the event set
	// incomplete (unreadable SSL payloads, content capture that never
	// attached, response data the capture missed). They limit what content
	// checks and response attestation can say, not whether events were
	// lost.
	Notes []string
}

// Assess judges completeness from a coverage record. A nil record means the
// capture did not say, which is not the same as complete.
func Assess(cov *models.Coverage) Completeness {
	if cov == nil {
		return Completeness{Reasons: []string{"coverage was not recorded (legacy or hand-written ground truth)"}}
	}

	names := make([]string, 0, len(cov.Probes))
	for name := range cov.Probes {
		names = append(names, name)
	}
	sort.Strings(names)

	var c Completeness
	for _, name := range names {
		p := cov.Probes[name]
		if !p.Ran {
			continue
		}
		if p.RingbufDrops > 0 {
			c.Reasons = append(c.Reasons, fmt.Sprintf("%s probe: kernel ring buffer discarded %d record(s)", name, p.RingbufDrops))
		}
		if p.UntrackedChildren > 0 {
			c.Reasons = append(c.Reasons, fmt.Sprintf("%s probe: tracked_pids map was full, %d descendant(s) (and their subtrees) went untracked", name, p.UntrackedChildren))
		}
		if p.StateMapFull > 0 {
			c.Reasons = append(c.Reasons, fmt.Sprintf("%s probe: a kernel state map was full, %d record(s) lost", name, p.StateMapFull))
		}
		if p.ChannelDrops > 0 {
			c.Reasons = append(c.Reasons, fmt.Sprintf("%s probe: events channel discarded %d event(s)", name, p.ChannelDrops))
		}
		if p.IOURingNetOps > 0 {
			c.Reasons = append(c.Reasons, fmt.Sprintf("%s probe: tracked processes submitted %d socket operation(s) through io_uring, which the syscall hooks do not see, so connections or sends may be missing", name, p.IOURingNetOps))
		}
		if p.QueueOverflow {
			c.Reasons = append(c.Reasons, fmt.Sprintf("%s probe: kernel fanotify queue overflowed", name))
		}
		if p.UndrainedRecords > 0 {
			c.Reasons = append(c.Reasons, fmt.Sprintf("%s probe: %d record(s) were still queued when the capture stopped and were never read", name, p.UndrainedRecords))
		}
		// The tree's share of the unresolved events is loss; the host-wide
		// count, which includes it, stays a note below (V-39, V-35).
		if p.UnresolvedInTree > 0 {
			c.Reasons = append(c.Reasons, fmt.Sprintf("%s probe: %d file event(s) by the agent's process tree had no resolvable path and are not in the capture (V-39)", name, p.UnresolvedInTree))
		}
		if p.HashlessCloses > 0 {
			c.Notes = append(c.Notes, fmt.Sprintf("%s probe: %d file close(s) were published without a content hash, so a claimed content for those is neither confirmed nor refuted", name, p.HashlessCloses))
		}
		if p.UnresolvedPaths > 0 {
			c.Notes = append(c.Notes, fmt.Sprintf("%s probe: %d file event(s) by any process had no resolvable path, because their directory was removed before they were read, and are not in the capture (V-35)", name, p.UnresolvedPaths))
		}
		if p.FaultedReads > 0 {
			c.Notes = append(c.Notes, fmt.Sprintf("%s probe: %d SSL payload read(s) faulted, request content is missing for those", name, p.FaultedReads))
		}
		if p.Content == models.ContentAttachFailed {
			c.Notes = append(c.Notes, fmt.Sprintf("%s probe: content capture failed to attach, identity only", name))
		}
		// With several content methods, one that read nothing while
		// another did leaves the probe's content active (N-42); each such
		// method gets its own note.
		if d := p.Diagnostics; d != nil && p.Content == models.ContentActive {
			for _, m := range sortedMethods(d.ContentMethods) {
				if st := d.ContentMethods[m]; st.Requests != models.ContentActive {
					c.Notes = append(c.Notes, fmt.Sprintf("%s probe: content method %s did not validate (%s), so claims that depend on it are not checked", name, m, st.Requests))
				}
			}
		}
		if p.HelloFaults > 0 {
			c.Notes = append(c.Notes, fmt.Sprintf("%s probe: %d ClientHello read(s) faulted, so a connection may be reported by address instead of hostname", name, p.HelloFaults))
		}
		// Responses are attestation that no claim depends on (N-29), so
		// their gaps and an inactive response capture are notes. A failed
		// request capture already has its note and implies this one.
		if p.Responses == models.ContentAttachFailed && p.Content != models.ContentAttachFailed {
			c.Notes = append(c.Notes, fmt.Sprintf("%s probe: response capture did not attach or never validated, so no response is attested", name))
		}
		if p.ResponseGaps > 0 {
			c.Notes = append(c.Notes, fmt.Sprintf("%s probe: %d response gap(s) (SSL_read data faulted, discarded, truncated or unparsed), so some responses are missing or attested incompletely; no claim depends on a response (N-29)", name, p.ResponseGaps))
		}
	}
	c.Complete = len(c.Reasons) == 0
	return c
}

// Outcome is what a verification run concludes once ground truth completeness
// is taken into account.
type Outcome int

const (
	// OutcomeFaithful: the checks passed and the ground truth is complete.
	OutcomeFaithful Outcome = iota
	// OutcomeNotFaithful: the checks found a discrepancy.
	OutcomeNotFaithful
	// OutcomeInconclusive: the checks passed but the ground truth may have
	// lost events, so FAITHFUL cannot be asserted.
	OutcomeInconclusive
)

func (o Outcome) String() string {
	switch o {
	case OutcomeFaithful:
		return "FAITHFUL"
	case OutcomeNotFaithful:
		return "NOT FAITHFUL"
	default:
		return "INCONCLUSIVE"
	}
}

// ExitCode is the process exit status for the outcome. Inconclusive gets its
// own code so a script cannot read it as a pass.
func (o Outcome) ExitCode() int {
	switch o {
	case OutcomeFaithful:
		return 0
	case OutcomeNotFaithful:
		return 1
	default:
		return 2
	}
}

// sortedMethods returns the content method names in order.
func sortedMethods(m map[string]models.ContentMethodState) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
