package claudecode

import (
	"net/url"

	"github.com/agent-trace/agent-trace/pkg/content"
)

func contentHash(s string) string { return content.SHA256Bytes([]byte(s)) }

// hostOf returns the hostname of a URL, or "" if it has none.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
