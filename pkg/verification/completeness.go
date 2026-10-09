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
	// attached). They limit what content checks can say, not whether events
	// were lost.
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
		if p.QueueOverflow {
			c.Reasons = append(c.Reasons, fmt.Sprintf("%s probe: kernel fanotify queue overflowed", name))
		}
		if p.HashlessCloses > 0 {
			c.Notes = append(c.Notes, fmt.Sprintf("%s probe: %d file close(s) were published without a content hash, so a claimed content for those is neither confirmed nor refuted", name, p.HashlessCloses))
		}
		if p.FaultedReads > 0 {
			c.Notes = append(c.Notes, fmt.Sprintf("%s probe: %d SSL payload read(s) faulted, request content is missing for those", name, p.FaultedReads))
		}
		if p.Content == models.ContentAttachFailed {
			c.Notes = append(c.Notes, fmt.Sprintf("%s probe: content capture failed to attach, identity only", name))
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
