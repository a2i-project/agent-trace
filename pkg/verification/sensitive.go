package verification

import (
	"fmt"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// SensitiveChange is one change the capture's snapshot found in a declared
// security-sensitive harness file between the start and the stop of the
// capture (V-40): the file, the key path and the kind. It holds no value.
type SensitiveChange struct {
	// File is the file as the adapter declares it ("~/.claude.json").
	File string `json:"file"`
	// Path is the file the declaration resolved to in this capture.
	Path string `json:"path"`
	models.SensitiveChange
}

// SensitiveFile is one declared file as the capture's snapshot found it.
type SensitiveFile struct {
	// File is the declaration and Path its resolution; Path is empty when
	// the snapshot does not name the file.
	File, Path string
	// Recorded is true when the snapshot names the file.
	Recorded bool
	// Start and Stop are its states at the two ends (models.Sensitive*).
	Start, Stop string
	// Baselined is true when the baseline's controls measured the file at
	// both ends, so its changes can be compared with theirs.
	Baselined bool
	// Changes are the snapshot's changes of the file.
	Changes []SensitiveChange
}

// SensitiveInput is the snapshot of the harness's declared sensitive files
// and what the baseline knows of them (V-40). A nil *SensitiveInput, a
// capture without a snapshot, checks nothing and reports nothing.
type SensitiveInput struct {
	// Files holds one entry per file the adapter declares.
	Files []SensitiveFile
	// Explained says whether the controls made a change. Nil when the
	// baseline holds no record of the sensitive files (or there is none):
	// no change is then checked, and a limitation says so.
	Explained func(SensitiveChange) bool
}

// SensitiveCheck is what the check of the sensitive files did. Its counts
// are over the changes that were checked; Unchecked holds the rest.
type SensitiveCheck struct {
	// Snapshot is true when the capture holds a snapshot.
	Snapshot bool
	// Checked is true when the baseline holds a record, so changes were
	// compared with the controls'.
	Checked bool
	// Files is how many declared files were checked.
	Files int
	// Changes is how many changes of checked files the snapshot shows;
	// Baselined, Claimed and len(Verdict.UnexplainedSensitiveChanges) split
	// them.
	Changes   int
	Baselined int
	// Claimed counts the changes a write-class claim of the file, or a
	// write of it beneath a command no baseline rule explains, accounts for.
	Claimed int
	// Unchecked are the changes of files that could not be checked: no
	// baseline record, or a file the controls did not measure. Not
	// findings; listed for the reader.
	Unchecked []SensitiveChange
	// Limitations say what could not be checked and why.
	Limitations []string
}

// checkSensitive compares the snapshot's changes with the controls' (V-40).
// A change is explained when the baseline holds it, when a write-class
// claim names exactly the file, or when a write-class event on exactly the
// file lies beneath a command no baseline rule explains: that command is
// claimed, so its subtree is (D3), or it is itself a finding. Every other
// change of a checked file is returned as unexplained.
func checkSensitive(in *SensitiveInput, claims models.Trajectory, cmds []*Command) ([]SensitiveChange, SensitiveCheck) {
	var check SensitiveCheck
	if in == nil {
		return nil, check
	}
	check.Snapshot = true
	check.Checked = in.Explained != nil
	claimed := map[string]bool{}
	for _, c := range claims {
		if writeClass(c.ActionType) && !implied(c) {
			claimed[c.Target] = true
		}
	}
	for _, cmd := range cmds {
		if cmd.Baseline {
			continue
		}
		for _, e := range cmd.Content {
			if writeClass(e.ActionType) {
				claimed[e.Target] = true
			}
		}
	}
	var unexplained []SensitiveChange
	total := 0
	for _, f := range in.Files {
		total += len(f.Changes)
		switch {
		case !f.Recorded:
			check.Limitations = append(check.Limitations, fmt.Sprintf("the snapshot does not name the declared file %s, so a change of it is not checked (V-40)", f.File))
			continue
		case len(f.Changes) == 0 && (!measuredState(f.Start) || !measuredState(f.Stop)):
			check.Limitations = append(check.Limitations, fmt.Sprintf("%s was not read (%s at start, %s at stop), so a change of it is not seen (V-40)", f.Path, f.Start, f.Stop))
			continue
		}
		if !check.Checked {
			check.Unchecked = append(check.Unchecked, f.Changes...)
			continue
		}
		if !f.Baselined {
			check.Unchecked = append(check.Unchecked, f.Changes...)
			check.Limitations = append(check.Limitations, fmt.Sprintf("the baseline's controls did not measure %s at both ends, so its %d change(s) are not checked (V-40)", f.File, len(f.Changes)))
			continue
		}
		check.Files++
		for _, c := range f.Changes {
			check.Changes++
			switch {
			case in.Explained(c):
				check.Baselined++
			case claimed[c.Path]:
				check.Claimed++
			default:
				unexplained = append(unexplained, c)
			}
		}
	}
	if !check.Checked {
		check.Limitations = append(check.Limitations, fmt.Sprintf("the baseline holds no record of what the controls changed in the harness's sensitive files (none supplied, or built from controls without a snapshot), so the %d change(s) the snapshot shows in them are not checked (V-40)", total))
	} else {
		check.Limitations = append(check.Limitations, "the snapshot compares each sensitive file at the start and the stop only, so a change made and reverted in between is not seen (V-40)")
	}
	return unexplained, check
}

func measuredState(s string) bool {
	return models.SensitiveState{State: s}.Measured()
}
