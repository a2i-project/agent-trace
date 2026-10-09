package verification

import (
	"sort"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// FSScope is the verifier's reading of a capture's fs_scope record: which
// file claims the capture could have witnessed at all. A claim it could not
// have witnessed is not aligned, because its absence from the ground truth
// says nothing about the agent, and it is listed as out of scope instead
// (V-23).
type FSScope struct {
	// legacy is true for a capture with no record: the probe then kept only
	// paths under the workspace, from any process.
	legacy    bool
	workspace string
	// mounts holds the marked mount points and the unmarked ones, each with
	// whether it was marked, so a path resolves to the longest matching mount
	// point and is in scope only if that one was marked.
	mounts []scopedMount
}

type scopedMount struct {
	point  string
	marked bool
}

// NewFSScope builds the reading from a capture's record and workspace. A nil
// record with no workspace means nothing is known, and every claim is in
// scope: the reading before fs_scope existed, for a caller that drives Verify
// directly.
func NewFSScope(rec *models.FSScope, workspace string) FSScope {
	if rec == nil {
		return FSScope{legacy: true, workspace: workspace}
	}
	var s FSScope
	for _, m := range rec.Mounts {
		s.mounts = append(s.mounts, scopedMount{point: m, marked: true})
	}
	for m := range rec.Unmarked {
		s.mounts = append(s.mounts, scopedMount{point: m, marked: false})
	}
	// Longest mount point first, so a path under /mnt/x/merged resolves to
	// that mount and not to /.
	sort.Slice(s.mounts, func(i, j int) bool { return len(s.mounts[i].point) > len(s.mounts[j].point) })
	return s
}

// Contains reports whether a file claim on path could have been observed by
// the capture.
func (s FSScope) Contains(path string) bool {
	if s.legacy {
		return s.workspace == "" || underDir(path, s.workspace)
	}
	for _, m := range s.mounts {
		if underDir(path, m.point) {
			return m.marked
		}
	}
	// No mount point covers the path: the capture listed none for it, which
	// means the probe was not looking there.
	return len(s.mounts) == 0
}

// underDir reports whether path is dir or inside it. A plain prefix test
// would let /ws admit /ws2.
func underDir(path, dir string) bool {
	if dir == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// splitByScope separates the file claims the capture could not have witnessed
// from the rest. Other lanes are untouched: the process and network probes
// have no path scope.
func splitByScope(claims models.Trajectory, scope FSScope) (inScope, outOfScope models.Trajectory) {
	for _, c := range claims {
		if LaneOf(c.ActionType) == LaneFS && !scope.Contains(c.Target) {
			outOfScope = append(outOfScope, c)
			continue
		}
		inScope = append(inScope, c)
	}
	return inScope, outOfScope
}
