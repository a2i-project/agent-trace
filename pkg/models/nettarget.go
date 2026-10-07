package models

import (
	"strconv"
	"strings"
)

// CanonicalNetTarget assembles the canonical Target string for a NetRequest
// action. It is called identically when building a GroundTruthEvent from
// observed traffic and when ingesting a trajectory entry's claimed URL, so
// that matching.Match's strict string equality (the same anti-normalization
// discipline as F2.2's command matching) is sufficient for NetRequest --
// see docs/architecture/13_probe_net.md.
//
// The form is:
//
//	<METHOD> https://<host>[:<port>]<path>[?<query>]
//
// No transformation beyond what's stated below is applied on either side:
//
//   - scheme is always "https", since this describes traffic observed (or
//     claimed) over TLS.
//   - host is lowercased.
//   - port is omitted when 443 (the default for https) or when <= 0
//     (meaning "not specified"); included otherwise.
//   - path is carried verbatim, never decoded or collapsed.
//   - query is carried verbatim, including its original ordering, and is
//     included (prefixed by '?') only when non-empty. Fragments have no
//     place here: they never appear over the wire and must be stripped by
//     the caller before this is called.
func CanonicalNetTarget(method, host string, port int, path, query string) string {
	var b strings.Builder
	b.WriteString(method)
	b.WriteString(" https://")
	b.WriteString(strings.ToLower(host))
	if port > 0 && port != 443 {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(port))
	}
	b.WriteString(path)
	if query != "" {
		b.WriteByte('?')
		b.WriteString(query)
	}
	return b.String()
}
