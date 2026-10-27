package claudecode

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// A WebFetch runs in the agent's own process (I-16). On 2.1.306 the tool
// (**Reported**, from the strings of the binary) first looks the URL up in
// its cache of fetched pages, keyed by the URL as the model wrote it, and
// returns a hit without touching the network. Otherwise it rewrites an http
// URL to https, asks the model API whether the host may be fetched, with
// GET https://api.anthropic.com/api/web/domain_info?domain=<host>, unless a
// check of the same host allowed it within five minutes, and then fetches
// the URL with GET, following a redirect only within the same site. The
// capture of 2.1.306 shows the check, the connection to the host and the GET,
// all by the agent's process (I-72).

// webFetchVersions are the versions whose WebFetch claims its request and
// the harness's domain check (I-72): 2.1.306, whose binary was read and whose
// paired capture shows both.
var webFetchVersions = map[string]bool{"2.1.306": true}

// domainCheckURL is the harness's domain check before a fetch, to which the
// host is appended.
const domainCheckURL = "https://api.anthropic.com/api/web/domain_info?domain="

// webFetchClaims are the claims of a WebFetch of a version in
// webFetchVersions, in the order the harness acts: the domain check,
// harness-implied (V-52), the connection to the URL's host and the GET of the
// URL. The connection and the GET are harness-implied too when the call may
// have made no request: a URL an earlier WebFetch of the session named, which
// the harness may serve from its cache, or a result marked is_error, which
// the harness may have returned before or after the request. fetched records
// the URLs fetched so far. ok is false when the URL's request target cannot
// be predicted (fetchTarget); the call then keeps the connection alone, as
// before I-72.
func webFetchClaims(u toolUse, base models.TrajectoryEntry, res toolResult, fetched map[string]bool) (claims []models.TrajectoryEntry, ok bool) {
	var in struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(u.input, &in) != nil || in.URL == "" {
		return nil, false
	}
	target, host, ok := fetchTarget(in.URL)
	if !ok {
		return nil, false
	}
	optional := fetched[in.URL] || res.isError
	fetched[in.URL] = true
	by := toolWebFetch + " " + in.URL
	mk := func(a models.ActionType, t string, implied bool) models.TrajectoryEntry {
		e := base
		e.ActionType, e.Target = a, t
		if implied {
			e.ImpliedBy = by
		}
		return e
	}
	check := mk(models.NetRequest, "GET "+domainCheckURL+host, true)
	check.ImpliedBefore = true
	return []models.TrajectoryEntry{check, mk(models.NetConnect, host, optional), mk(models.NetRequest, target, optional)}, true
}

// fetchTarget is the target the net probe writes for the GET a WebFetch of
// raw makes (models.CanonicalNetTarget), and the URL's host, lowercased. The
// harness parses the URL with a WHATWG URL parser, which can rewrite a URL
// (percent-encoding, dot segments, IPv4 forms, default ports), so ok is false
// unless the URL is in a form that parser leaves as it is: http or https, no
// user information, a host of ASCII letters, digits, dots and dashes that is
// not an address, a port of plain digits, and a path and a query of
// characters it does not encode, with well-formed percent escapes and no dot
// segment. The fragment is never sent and is dropped; an http URL is fetched
// over https, so its default port goes and 443 stays out of the target.
func fetchTarget(raw string) (target, host string, ok bool) {
	var scheme, rest string
	switch lower := strings.ToLower(raw); {
	case strings.HasPrefix(lower, "https://"):
		scheme, rest = "https", raw[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		scheme, rest = "http", raw[len("http://"):]
	default:
		return "", "", false
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	authority, pathQuery := rest, ""
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		authority, pathQuery = rest[:i], rest[i:]
	}
	host, portText := authority, ""
	if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		host, portText = authority[:i], authority[i+1:]
	}
	host = strings.ToLower(host)
	if !plainHost(host) {
		return "", "", false
	}
	port := 0
	if portText != "" {
		p, err := strconv.Atoi(portText)
		if err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != portText {
			return "", "", false
		}
		if scheme != "http" || p != 80 {
			port = p
		}
	}
	path, query := pathQuery, ""
	if i := strings.IndexByte(pathQuery, '?'); i >= 0 {
		path, query = pathQuery[:i], pathQuery[i+1:]
	}
	if path == "" {
		path = "/"
	}
	if !unchanged(path, pathChars) || !unchanged(query, queryChars) || dotSegment(path) {
		return "", "", false
	}
	return models.CanonicalNetTarget("GET", host, port, path, query), host, true
}

// plainHost reports whether a lowercased host is a name of ASCII letters,
// digits, dots and dashes with at least one dot and no empty label, whose
// last label is not a number: the parser would read such a name as an IPv4
// address and rewrite it.
func plainHost(h string) bool {
	if !strings.Contains(h, ".") || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	last := h[strings.LastIndexByte(h, '.')+1:]
	if strings.HasPrefix(last, "0x") {
		return false
	}
	return strings.Trim(last, "0123456789") != ""
}

// pathChars and queryChars are the characters, beyond ASCII letters and
// digits, that the WHATWG parser leaves as they are in a path and in the
// query of an http or https URL; '%' is checked as an escape.
const (
	pathChars  = "-._~!$&'()*+,;=:@/%"
	queryChars = "-._~!$&()*+,;=:@/?%"
)

// unchanged reports whether s holds only letters, digits and allowed, with
// every '%' starting an escape of two hex digits.
func unchanged(s, allowed string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
		case strings.IndexByte(allowed, c) >= 0:
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// dotSegment reports whether a path has a segment the parser would resolve:
// "." or "..", plain or percent-encoded.
func dotSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		s := strings.ReplaceAll(strings.ToLower(seg), "%2e", ".")
		if s == "." || s == ".." {
			return true
		}
	}
	return false
}

// NeedsContent says which claims only a capture that read the agent's
// request content can witness: a WebFetch's requests (I-72). agent.Prepare
// drops them from a capture without it, which leaves the connection.
func (Adapter) NeedsContent(e models.TrajectoryEntry) bool {
	return e.Tool == toolWebFetch && e.ActionType == models.NetRequest
}
