package models

// FSMounts is one filesystem's mounts in the fs probe's mount namespace when
// the capture started, from /proc/self/mountinfo (P-33). A filesystem is one
// superblock: two mounts with the same Device reach the same files, each
// from its own Root.
type FSMounts struct {
	// Device is the superblock's device number as mountinfo gives it,
	// "major:minor".
	Device string `json:"device"`
	// FSType is the filesystem type, as mountinfo gives it.
	FSType string `json:"fstype"`
	// Mounts are the filesystem's mounts, in mountinfo order.
	Mounts []Mount `json:"mounts"`
}

// Mount is one mount of a filesystem: one line of /proc/self/mountinfo.
type Mount struct {
	// ID and Parent are the mount's id and its parent's id. A mount whose
	// parent is not in the table is the root of the namespace (or of the
	// process's root directory).
	ID     int `json:"id"`
	Parent int `json:"parent"`
	// Root is the directory within the filesystem the mount exposes: "/"
	// for the whole filesystem, a subdirectory for a bind of it. Point is
	// where the mount sits in the namespace. Both are unescaped; the kernel
	// appends "//deleted" to one that was removed.
	Root  string `json:"root"`
	Point string `json:"point"`
	// Names is true for the mount the fs probe names this filesystem's files
	// through (P-30). At most one mount per filesystem carries it; a
	// filesystem the probe did not mark has none.
	Names bool `json:"names,omitempty"`
}
