package claudecode

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Claude Code keeps edit checkpoints ("file history") so that a user can
// rewind the session's file changes (V-104). The binary of 2.1.306
// (**Reported**, from its strings) keeps them under
// <config dir>/file-history/<session id>/ and names a file's version n
// <first 16 hex digits of the SHA-256 of the file's path>@v<n>. At its
// first edit of a file it copies the file there as v1, and at the start
// of each later prompt it copies, as the next version, every file the
// session has edited, reading each with the agent's own process. Print
// mode has one prompt, so only an interactive session makes the later
// copies. On the first interactive capture of 2.1.306 each of its eight
// later copies is an open of the file by the agent's process followed by
// that process's open, write and close of the version file, whose output
// hash is the open's input hash, and the version's name is the file's
// path hashed as above (**Verified**, local only).

// checkpointVersions are the versions whose checkpoints are declared.
var checkpointVersions = map[string]bool{"2.1.306": true}

// checkpointName is the base name of a checkpoint version, its hash and
// its version number as the binary's own check of it reads them.
var checkpointName = regexp.MustCompile(`^([0-9a-f]{16})@v[1-9][0-9]*$`)

// declareCheckpoint returns the checkpoint declaration of TraceDecl for a
// session id and version: written is a version of file when it is
// <home>/.claude/file-history/<id>/<hash of file>@v<n>, file absolute and
// clean. The home is the capture's when it recorded one, else any home
// I-30 declares. Nil for a version not in checkpointVersions or an id that
// is not a session id.
func declareCheckpoint(home, id, version string) func(file, written string) bool {
	if !checkpointVersions[version] || !sessionIDPattern.MatchString(id) {
		return nil
	}
	if home != "" && (home != filepath.Clean(home) || !homePattern.MatchString(home)) {
		return nil
	}
	return func(file, written string) bool {
		if file == "" || !filepath.IsAbs(file) || file != filepath.Clean(file) {
			return false
		}
		dir, name := filepath.Split(written)
		m := checkpointName.FindStringSubmatch(name)
		if m == nil {
			return false
		}
		sum := sha256.Sum256([]byte(file))
		if m[1] != hex.EncodeToString(sum[:])[:16] {
			return false
		}
		rest, ok := strings.CutSuffix(dir, "/.claude/file-history/"+id+"/")
		if !ok {
			return false
		}
		if home != "" {
			return rest == home
		}
		return homePattern.MatchString(rest)
	}
}

// checkpointFile is a checkpoint version path in any session's directory
// under any home I-30 declares, with its name's hash.
var checkpointFile = regexp.MustCompile(`^/(?:home/[^/]+|root)/\.claude/file-history/` + uuidPattern + `/([0-9a-f]{16})@v[1-9][0-9]*$`)

// checkpointCopy is the first event of a process on a checkpoint version:
// the hash its name holds and the output hash of that process's first
// close of it, empty when the probe reported none.
type checkpointCopy struct {
	name, content string
}

// of reports whether open is the copy's source: an open of the file the
// version's name hashes, by the same process, with the version's content.
func (c checkpointCopy) of(open models.GroundTruthEvent) bool {
	if c.name == "" || c.content == "" || open.InputHash == nil || *open.InputHash != c.content || open.PathIsAmbiguous || open.TargetTruncated {
		return false
	}
	sum := sha256.Sum256([]byte(open.Target))
	return hex.EncodeToString(sum[:])[:16] == c.name
}

// checkpointCopies indexes, by its position in g, the first event of each
// process on each checkpoint version path, with what checkpointCopy holds
// (V-104). collapseOpens uses it to end a run that is only the copy's open;
// the session and the version are not known there, so the path is matched
// for any session, and the verifier decides with the session's declaration
// (declareCheckpoint) what the copy explains.
func checkpointCopies(g models.GroundTruth) map[int]checkpointCopy {
	type key struct {
		pid  uint32
		path string
	}
	first := map[key]int{}
	var out map[int]checkpointCopy
	for i, e := range g {
		if e.PID == 0 || e.PathIsAmbiguous || e.TargetTruncated || !isFile(e.ActionType) {
			continue
		}
		m := checkpointFile.FindStringSubmatch(e.Target)
		if m == nil {
			continue
		}
		k := key{e.PID, e.Target}
		at, seen := first[k]
		if !seen {
			first[k] = i
			if out == nil {
				out = map[int]checkpointCopy{}
			}
			out[i] = checkpointCopy{name: m[1]}
			at = i
		}
		if c := out[at]; e.ActionType == models.FileClose && e.OutputHash != nil && c.content == "" {
			c.content = *e.OutputHash
			out[at] = c
		}
	}
	return out
}
