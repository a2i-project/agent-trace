package models

import (
	"net"
	"strings"
)

// Exposure says who can reach a listening address.
type Exposure string

const (
	// ExposureLoopback: only processes on this host.
	ExposureLoopback Exposure = "loopback"
	// ExposureWildcard: every interface, so reachable from the network.
	ExposureWildcard Exposure = "wildcard"
	// ExposureInterface: one specific non-loopback address.
	ExposureInterface Exposure = "interface"
	// ExposureUnknown: the probe did not see the address (listen on a socket
	// that was never bound through bind()), or the target did not parse.
	ExposureUnknown Exposure = "unknown"
)

// UnboundListenTarget is the Target of a NetListen event whose address the
// probe could not see.
const UnboundListenTarget = "unbound"

// ClassifyBindTarget returns the exposure of a NetBind or NetListen Target of
// the form host:port, as written by the net probe (IPv6 in brackets). The
// distinction matters because a wildcard listener is reachable off the host,
// which is what makes a listener inside a command's subtree a capability
// worth reporting.
func ClassifyBindTarget(target string) Exposure {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return ExposureUnknown
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	switch {
	case ip == nil:
		return ExposureUnknown
	case ip.IsUnspecified():
		return ExposureWildcard
	case ip.IsLoopback():
		return ExposureLoopback
	default:
		return ExposureInterface
	}
}
