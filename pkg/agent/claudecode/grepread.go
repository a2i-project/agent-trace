package claudecode

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// A Grep whose path names a file reads that file in the agent's own process
// before it starts its search (I-69). The harness opens the path itself,
// read-only and without blocking, to check where it leads; for a regular file
// on Linux it then starts its embedded ripgrep on /proc/self/fd/3, the file it
// opened, passed as descriptor 3, instead of on the path. The probe sees a
// level-0 open of the file and then ripgrep's open of the same file, which
// the kernel names by its path. For a directory the harness's open is of the
// directory, which the probe does not record, and ripgrep reads the files.
// Whether the path is a file or a directory the transcript does not say, so
// the open is claimed as harness-implied (V-33): it costs nothing unpaired,
// and pairs only with an open of exactly the path that a search's ripgrep
// opened too, no earlier than the harness did (V-48).

// grepOpenVersions are the versions whose binary was read for the rule: in
// 2.1.296 and 2.1.306 the Grep tool's path check opens the path and hands a
// regular file to ripgrep as /proc/self/fd/3 (**Reported**, from their
// strings). The binary of 2.1.286 was not read.
var grepOpenVersions = map[string]bool{"2.1.296": true, "2.1.306": true}

// grepOpenClaims is the harness-implied open of the path a Grep names, after
// the call's own claim and with its interval, thread and block, marked with
// the kind of search and as coming before it. None when the input names no
// path or one starting with "~", or when the working directory is not
// recorded, is not absolute, or changed between the call and its result.
func grepOpenClaims(u toolUse, base models.TrajectoryEntry, res toolResult) []models.TrajectoryEntry {
	var in struct {
		Path string `json:"path"`
	}
	if json.Unmarshal(u.input, &in) != nil || in.Path == "" || strings.HasPrefix(in.Path, "~") {
		return nil
	}
	if u.cwd == "" || res.cwd != u.cwd || !filepath.IsAbs(u.cwd) {
		return nil
	}
	e := base
	e.ActionType, e.Target = models.FileOpen, resolveRead(u.cwd, in.Path)
	e.ImpliedBy, e.ImpliedBefore = SearchGrep, true
	return []models.TrajectoryEntry{e}
}
