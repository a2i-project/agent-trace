package models

// The states a snapshot can find a security-sensitive harness file in
// (V-40). Only SensitivePresent and SensitiveMissing are measurements; the
// others say why the file was not read.
const (
	// SensitivePresent: a regular file owned by the agent's user, read whole.
	SensitivePresent = "present"
	// SensitiveMissing: no file at the path.
	SensitiveMissing = "missing"
	// SensitiveNotRegular: the path names something other than a regular
	// file (a directory, a FIFO, a device), which is not read.
	SensitiveNotRegular = "not-regular"
	// SensitiveForeign: a regular file owned by another user than the
	// agent's. Not read, since the recorder runs as root and the file is
	// not the harness's (a symbolic link to a file of root's, say).
	SensitiveForeign = "foreign"
	// SensitiveTooLarge: larger than the snapshot reads.
	SensitiveTooLarge = "too-large"
	// SensitiveUnreadable: opening or reading the file failed.
	SensitiveUnreadable = "unreadable"
)

// The formats a present file is summarised in.
const (
	// SensitiveJSON: the file parsed as JSON and is summarised by key path.
	SensitiveJSON = "json"
	// SensitiveOther: anything else, summarised by one hash of its bytes.
	SensitiveOther = "other"
)

// The kinds of change a snapshot records between Start and Stop (V-40).
const (
	// SensitiveCreated: missing at Start, present at Stop.
	SensitiveCreated = "created"
	// SensitiveDeleted: present at Start, missing at Stop.
	SensitiveDeleted = "deleted"
	// SensitiveContent: a file that is not JSON at one end changed bytes.
	SensitiveContent = "content"
	// SensitiveUnmeasured: the file's state changed and one end is not a
	// measurement (it became a FIFO, a file of another user, too large).
	SensitiveUnmeasured = "unmeasured"
	// SensitiveAdded: a key path present at Stop only.
	SensitiveAdded = "added"
	// SensitiveRemoved: a key path present at Start only.
	SensitiveRemoved = "removed"
	// SensitiveChanged: a key path whose value changed, or changed from a
	// list to a single value or back.
	SensitiveChanged = "changed"
	// SensitiveEntriesAdded: entries of a list that were not in it at Start.
	SensitiveEntriesAdded = "entries-added"
	// SensitiveEntriesRemoved: entries of a list that are not in it at Stop.
	SensitiveEntriesRemoved = "entries-removed"
)

// SensitiveSnapshot is what cmd/watch recorded of the harness's
// security-sensitive files, as the adapters declare them, at the start and
// at the stop of a capture (V-40, I-59). It records no content: each end is
// a state and a keyed digest, and the changes name key paths and kinds only.
// The key of the digests is random per capture and is never written, so a
// digest says only whether the two ends are equal.
type SensitiveSnapshot struct {
	// Home is the directory a declared "~/" was resolved against: the home
	// of the user the agent ran as.
	Home string `json:"home"`
	// Files holds one entry per declared file, in declaration order.
	Files []SensitiveFile `json:"files"`
}

// SensitiveFile is one declared file at both ends of the capture.
type SensitiveFile struct {
	// Declared is the file as the adapter declares it, with "~/" or
	// "{workspace}/" in front.
	Declared string `json:"declared"`
	// Path is the file the declaration resolved to.
	Path  string         `json:"path"`
	Start SensitiveState `json:"start"`
	Stop  SensitiveState `json:"stop"`
	// Changes are the differences between the two ends, in key-path order.
	// Empty when nothing changed or an end was not measured.
	Changes []SensitiveChange `json:"changes,omitempty"`
}

// SensitiveState is a file at one end of the capture.
type SensitiveState struct {
	// State is one of the Sensitive* states.
	State string `json:"state"`
	// Format is SensitiveJSON or SensitiveOther for a present file.
	Format string `json:"format,omitempty"`
	// Digest is the keyed hash of the whole file, for a present file.
	Digest string `json:"digest,omitempty"`
	// Error says why an unreadable file could not be read.
	Error string `json:"error,omitempty"`
}

// Measured reports whether the state is a measurement of the file: present
// and read, or missing.
func (s SensitiveState) Measured() bool {
	return s.State == SensitivePresent || s.State == SensitiveMissing
}

// SensitiveChange is one difference between the two ends of a file.
type SensitiveChange struct {
	// Key is the JSON key path, one element per object key from the root.
	// Empty for a change of the whole file (created, deleted, content,
	// unmeasured) and for a list at the root.
	Key []string `json:"key,omitempty"`
	// Kind is one of the Sensitive change kinds.
	Kind string `json:"kind"`
	// Entries is how many list entries were added or removed, for the two
	// entries kinds.
	Entries int `json:"entries,omitempty"`
}
