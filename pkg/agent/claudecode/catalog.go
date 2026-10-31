package claudecode

import (
	"path/filepath"
	"regexp"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Claude Code 2.1.306 caches the model catalog its API serves to an
// account (V-58). The binary (**Reported**, from its strings) keeps the
// cache under ~/.claude/cache/model-catalog/, names an account's entry
// <organization id>-<account scope>-<surface>.json, and writes it with its
// atomic write: a temporary <path>.tmp.<8 hex digits> renamed onto the
// entry. The fourth websearch capture of 2.1.306 shows it once, in the task
// run, 0.2 s after the GET of the organization's model selector (V-57), by
// the agent's own process: the temporary created, opened, written, closed
// and renamed, then the rename onto <uuid>-<12 hex>-cc.json, all within one
// microsecond, which NormalizeStream folds into one write of the entry. Its
// controls only open the entry, which the baseline explains.

// catalogVersions are the versions whose catalog cache write is declared.
var catalogVersions = map[string]bool{"2.1.306": true}

// catalogSourceWindow bounds how long before a rename onto the entry the
// rename of its temporary may come, in the shape NormalizeStream does not
// fold. The capture shows both in the same microsecond.
const catalogSourceWindow = time.Second

// CaptureBookkeeping declares, for the versions in catalogVersions, the
// harness's write of an account's model-catalog cache entry in exactly the
// shape of its atomic write (V-58): on a temporary
// ~/.claude/cache/model-catalog/<uuid>-<12 hex>-cc.json.tmp.<8 hex>, the
// kinds of tempKinds; on the entry, the write the fold makes of the replace,
// only when the raw capture holds the create of such a temporary of the
// entry by the same process at the same time (the fold stamps the write at
// the create), and a rename onto the entry, only when the raw capture holds
// the rename of such a temporary by the same process at most
// catalogSourceWindow before it. The file tools name their temporaries
// <path>.tmp.<pid>.<12 hex>, so an agent's Write of the entry is never
// recognised. An open, a delete, another surface, the mask and floor files
// beside the entry, and every other file there stay unexplained harness
// activity. The home is as for HarnessBookkeeping.
func (Adapter) CaptureBookkeeping(version, home string, raw models.GroundTruth) func(models.GroundTruthEvent) bool {
	if !catalogVersions[version] {
		return nil
	}
	h := `/(?:home/[^/]+|root)`
	if home != "" {
		if home != filepath.Clean(home) || !homePattern.MatchString(home) {
			return nil
		}
		h = regexp.QuoteMeta(home)
	}
	entry := regexp.MustCompile(`^(` + h + `/\.claude/cache/model-catalog/` + uuidPattern + `-[0-9a-f]{12}-cc\.json)(\.tmp\.[0-9a-f]{8})?$`)
	type key struct {
		pid    uint32
		target string
	}
	creates := map[key][]time.Time{}
	sources := map[key][]time.Time{}
	for _, e := range raw {
		m := entry.FindStringSubmatch(e.Target)
		if m == nil || m[2] == "" || e.PathIsAmbiguous || e.PID == 0 {
			continue
		}
		k := key{e.PID, m[1]}
		switch e.ActionType {
		case models.FileWrite:
			creates[k] = append(creates[k], e.Timestamp)
		case models.FileRename:
			sources[k] = append(sources[k], e.Timestamp)
		}
	}
	if len(creates) == 0 && len(sources) == 0 {
		return nil
	}
	return func(e models.GroundTruthEvent) bool {
		m := entry.FindStringSubmatch(e.Target)
		if m == nil || e.PathIsAmbiguous || e.PID == 0 {
			return false
		}
		if m[2] != "" {
			return tempKinds[e.ActionType]
		}
		k := key{e.PID, m[1]}
		switch e.ActionType {
		case models.FileWrite:
			for _, t := range creates[k] {
				if t.Equal(e.Timestamp) {
					return true
				}
			}
		case models.FileRename:
			for _, t := range sources[k] {
				if !t.After(e.Timestamp) && e.Timestamp.Sub(t) <= catalogSourceWindow {
					return true
				}
			}
		}
		return false
	}
}
