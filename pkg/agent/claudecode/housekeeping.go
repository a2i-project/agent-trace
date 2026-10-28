package claudecode

import (
	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// Claude Code renews its login token when the token nears expiry (V-54). On
// 2.1.306 (**Reported**, from the strings of the binary, which 2.1.302 and
// 2.1.311 share) the renewal POSTs a JSON body with grant_type
// refresh_token, the refresh token, the client id and the scopes to
// TOKEN_URL, https://platform.claude.com/v1/oauth/token, and then reads the
// account with GET https://api.anthropic.com/api/oauth/profile, carrying the
// new token in a header and no body; neither URL has a query. Two runs
// among all the raw captures on this machine show it, each within a second
// of start and by the agent's own process: the task run of the websearch
// capture of 2.1.306 (the connection to platform.claude.com, the POST and
// the GET) and one control of the second long pilot of 2.1.306 (the same,
// each request reported twice). No other run connects to
// platform.claude.com.

// housekeepingVersions are the versions whose token renewal is declared:
// 2.1.306, whose binary was read and whose capture shows the renewal.
var housekeepingVersions = map[string]bool{"2.1.306": true}

// tokenRenewal is the renewal as the net probe writes it: the connection to
// the token endpoint's host, the POST with its body, and the GET of the
// profile with none. The profile's host, api.anthropic.com, is the model
// API's, to which every run connects, so the baseline explains that
// connection and it is not declared.
var tokenRenewal = []agent.Housekeeping{
	{ActionType: models.NetConnect, Target: "platform.claude.com"},
	{ActionType: models.NetRequest, Target: "POST https://platform.claude.com/v1/oauth/token", Body: true},
	{ActionType: models.NetRequest, Target: "GET https://api.anthropic.com/api/oauth/profile"},
}

// HarnessHousekeeping declares the token renewal of the versions in
// housekeepingVersions as the harness's own network housekeeping (V-54).
// Any other version declares nothing: an endpoint not read in a version's
// binary is not declared. A harness pointed at another OAuth endpoint (the
// binary reads an override from its environment) renews at other targets,
// which stay unexplained.
func (Adapter) HarnessHousekeeping(version string) []agent.Housekeeping {
	if !housekeepingVersions[version] {
		return nil
	}
	return append([]agent.Housekeeping(nil), tokenRenewal...)
}
