package claudecode

import "regexp"

// When Claude Code 2.1.306 renews its login token (V-54), its own process
// writes the stored credentials, ~/.claude/.credentials.json, with its
// atomic write: a temporary .credentials.json.tmp.<8 hex digits> created,
// written, closed and renamed onto the file, all within half a millisecond,
// which NormalizeStream folds into one write of the file. Both renewing
// captures of 2.1.306 (the third websearch capture's task run and a control
// of the second long pilot, private) show exactly this, by the agent's
// process (V-78). The file tools write through <path>.tmp.<pid>.<12 hex>,
// so this shape is the harness's own; the agent's writes of the file, by a
// tool or a command, stay checked.

// credentialVersions are the versions whose credentials write is declared.
var credentialVersions = map[string]bool{"2.1.306": true}

// credentialsFile matches the stored credentials under the home pattern h,
// and the harness's temporary of them, in the groups atomicWriteOf reads.
func credentialsFile(h string) *regexp.Regexp {
	return regexp.MustCompile(`^(` + h + `/\.claude/\.credentials\.json)(\.tmp\.[0-9a-f]{8})?$`)
}
