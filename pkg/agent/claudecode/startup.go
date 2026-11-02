package claudecode

import (
	"path/filepath"
	"regexp"
)

// Claude Code reads a set of its own files while it starts and never sends
// their content to the model (V-82). The timing study of 2026-11-02 measured
// every level-0 open of them on the Claude Code captures of 2.1.296 and
// 2.1.306 at hand (the checked-in fixtures and the private captures,
// controls included): with the boundary of V-82, no honest open of them came
// after the start-up except within two seconds of the harness's own write of
// the same file. The families, under the home:
//
//   - the stored credentials, .claude/.credentials.json;
//   - the user settings, .claude/settings.json;
//   - the policy limits, .claude/policy-limits.json and its .signature.json,
//     .signature-iat.json and .stamp.json;
//   - the remote settings, .claude/remote-settings.json and its
//     .signature.json, .signature-iat.json and .synced-at;
//   - the MCP caches, .claude/mcp-needs-auth-cache.json and
//     .claude/state/mcp-discover-verdicts.json;
//   - the model catalog, .claude/cache/model-catalog/<name>.json;
//   - the marketplace manifests, .claude/plugins/known_marketplaces.json and
//     .claude/plugins/marketplaces/<name>/.claude-plugin/marketplace.json;
//   - the version binary, .local/share/claude/versions/<version>, of the
//     session's own version;
//   - the global instructions, .claude/CLAUDE.md.
//
// The study's start-up set also held the harness's file-watch probe
// (/tmp/claude-<uid>/fswatch-probe-<random>/probe, an empty file it creates
// and deletes), the home and ~/.claude directories, and the backups of
// ~/.claude.json under .claude/backups/; none is declared. The probe and the
// directories hold nothing to hide, and a backup holds what ~/.claude.json
// holds, which the harness reads at irregular times and whose reads stay
// hidden (V-36). System libraries and certificates are public and were not
// part of the study's set.

// startupVersions are the versions whose start-up files are declared: those
// the timing study measured.
var startupVersions = map[string]bool{"2.1.296": true, "2.1.306": true}

// StartupFiles declares the harness's start-up-only files above for the
// versions in startupVersions (V-82). The home is the one the capture
// resolved "~/" against when it recorded one, else any home I-30 declares.
// Any other version, or a home that is not a clean one of that shape,
// declares nothing.
func (Adapter) StartupFiles(version, home string) func(path string) bool {
	if !startupVersions[version] {
		return nil
	}
	h := `/(?:home/[^/]+|root)`
	if home != "" {
		if home != filepath.Clean(home) || !homePattern.MatchString(home) {
			return nil
		}
		h = regexp.QuoteMeta(home)
	}
	files := regexp.MustCompile(`^` + h + `/(?:\.claude/(?:` +
		`\.credentials\.json` +
		`|settings\.json` +
		`|policy-limits\.json(?:\.signature\.json|\.signature-iat\.json|\.stamp\.json)?` +
		`|remote-settings\.json(?:\.signature\.json|\.signature-iat\.json|\.synced-at)?` +
		`|mcp-needs-auth-cache\.json` +
		`|state/mcp-discover-verdicts\.json` +
		`|cache/model-catalog/[^/]+\.json` +
		`|plugins/known_marketplaces\.json` +
		`|plugins/marketplaces/[^/]+/\.claude-plugin/marketplace\.json` +
		`|CLAUDE\.md` +
		`)|\.local/share/claude/versions/` + regexp.QuoteMeta(version) + `)$`)
	return files.MatchString
}
