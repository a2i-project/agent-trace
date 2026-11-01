package models

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// CoverageSchema is the version of the coverage record this build writes.
// Schema 2 added ProbeCoverage.Diagnostics and changed nothing else, so a
// schema 1 record reads as before, with nil Diagnostics. A file with a version
// outside MinCoverageSchema to CoverageSchema is rejected rather than guessed
// at.
const CoverageSchema = 2

// MinCoverageSchema is the oldest coverage record this build reads.
const MinCoverageSchema = 1

// Content states for ProbeCoverage.Content (net probe only).
const (
	ContentActive       = "active"
	ContentIdentityOnly = "identity_only"
	ContentAttachFailed = "attach_failed"
)

// ProbeCoverage holds one probe's raw loss counters for a capture run. It
// stores counters only. Whether a run is complete is a judgement the verifier
// makes (see pkg/verification.Assess), not something the probe asserts.
type ProbeCoverage struct {
	// Ran is false for a probe that was not started. Absence of its events
	// then says nothing about whether the agent performed such actions.
	Ran bool `json:"ran"`
	// RingbufDrops counts records the kernel ring buffer discarded because it
	// was full. Those events never reached userspace.
	RingbufDrops uint64 `json:"ringbuf_drops"`
	// UntrackedChildren counts descendants of the tracked tree that the
	// kernel could not add to its tracked_pids map because it was full. Each
	// is invisible to the probe along with everything it forks afterwards, so
	// this is event loss. One increment can stand for a whole subtree: a
	// lower bound, meaningful only as zero versus non-zero.
	UntrackedChildren uint64 `json:"untracked_children"`
	// StateMapFull counts records lost because a per-process (proc: exit
	// records) or per-connection (net: connections) kernel state map was
	// full, so the entry could not be stored. Event loss. A lower bound.
	StateMapFull uint64 `json:"state_map_full"`
	// ChannelDrops counts events userspace discarded because the Go events
	// channel was full.
	ChannelDrops uint64 `json:"channel_drops"`
	// HashlessCloses counts the file closes that carry no content hash: a
	// newer close, a write-class event or an open by the closing process
	// arrived before the content settled (P-16, P-39), the closing process
	// still held the file for writing (P-26), the file is not regular (P-35),
	// or the read failed. The probe counts every close it published on any
	// marked filesystem; cmd/watch replaces that with the closes the capture
	// keeps after its scope rule (P-40). A content gap, not event loss: the
	// close is in the capture, its content is not vouched for.
	HashlessCloses uint64 `json:"hashless_closes,omitempty"`
	// FaultedReads counts SSL_write calls whose plaintext could not be read.
	// A content gap, not an event loss. Net probe only.
	FaultedReads uint64 `json:"faulted_reads,omitempty"`
	// IOURingNetOps counts operations on sockets that tracked processes
	// submitted through io_uring, plus those whose target the probe could
	// not resolve. The net probe hooks only syscalls, which these bypass, so
	// a connection or a send may be missing: event loss (N-25). Net probe
	// only.
	IOURingNetOps uint64 `json:"io_uring_net_ops,omitempty"`
	// QueueOverflow reports a kernel fanotify queue overflow, meaning some
	// events were lost. Filesystem probe only.
	QueueOverflow bool `json:"queue_overflow,omitempty"`
	// Content is one of the Content* constants. Net probe only.
	Content string `json:"content,omitempty"`
	// HelloFaults counts reads of a connection's first bytes (the TLS
	// ClientHello) that faulted. The connection is still recorded and
	// counts as having sent data; its hostname may be missing, so it is
	// reported by address. A content gap, not an event loss. An upper bound
	// on the connections affected. Net probe only.
	HelloFaults uint64 `json:"hello_faults,omitempty"`
	// UndrainedRecords counts the fanotify records still queued when the fs
	// probe's stop drain ran out of time: events of the run that were never
	// read. Event loss, a lower bound. Filesystem probe only.
	UndrainedRecords uint64 `json:"undrained_records,omitempty"`
	// UnresolvedPaths counts the file events whose path no handle resolved,
	// one per action type of each record, from any process but the
	// recorder's: a delete or write in a directory removed before the event
	// was read. cmd/watch leaves them out of the capture and lists them by
	// type in FSScope.Unresolved. A note, not event loss (V-35).
	// Filesystem probe only.
	UnresolvedPaths uint64 `json:"unresolved_paths,omitempty"`
	// UnresolvedInTree counts the file events with no resolvable path whose
	// pid the process forest places in the agent's tree (the agent itself or
	// a descendant), one per action type, as FSScope.Unresolved counts them.
	// cmd/watch fills it after the capture, when every fork record is known;
	// the probe cannot, since it does not know the tree. Event loss (V-39).
	// Zero when the capture has no root pid, so there is no tree. A subset
	// of UnresolvedPaths. Filesystem probe only.
	UnresolvedInTree uint64 `json:"unresolved_in_tree,omitempty"`
	// Responses is the state of response capture (the SSL_read side of
	// content capture, N-29), one of the Content* constants: active once a
	// read of a tracked process validated the SSL_read offset. Empty in a
	// capture written before the field existed. Net probe only.
	Responses string `json:"responses,omitempty"`
	// ResponseGaps counts response data the capture may be missing: SSL_read
	// buffers that faulted or that the ring buffer discarded, responses
	// with bytes missed, and read streams that lost their place and were
	// skipped. A content gap on attestation, never event loss: no claim
	// depends on a response (N-29). Net probe only.
	ResponseGaps uint64 `json:"response_gaps,omitempty"`
	// Diagnostics holds the probe's occupancy and content counters (schema
	// 2). Nil means not measured: a capture written before the record, or a
	// probe that keeps none (fs). The verifier reads none of it.
	Diagnostics *ProbeDiagnostics `json:"diagnostics,omitempty"`
}

// ProbeDiagnostics says how close a capture came to its limits and how much
// of its network traffic had parsed content. It is measurement for the
// experiment record, not loss accounting: the loss counters above decide
// completeness, and verification.Assess reads nothing here, so no reason,
// note or verdict depends on it (P-34, N-33).
type ProbeDiagnostics struct {
	// Rings is keyed by the kernel ring buffer's map name: "events" (proc),
	// "net_events", "ssl_events" and "aead_events" (net; ssl_events only
	// when content capture was configured, aead_events only with the
	// tls-rustls-aead method).
	Rings map[string]RingStats `json:"rings,omitempty"`
	// TrackedSets is keyed by the eBPF object whose tracked_pids map it
	// describes: "proc", "net" and "tls" (tls only when content capture was
	// configured).
	TrackedSets map[string]TrackedSetStats `json:"tracked_sets,omitempty"`
	// NetContent holds the net probe's correlator counters. Net probe only.
	NetContent *NetContentCounts `json:"net_content,omitempty"`
	// SSLWrites holds the net probe's per-call SSL_write counts (N-36). Nil
	// means not measured: no content capture, an offset that never
	// validated, or a capture written before the field. Net probe only.
	SSLWrites *SSLWriteCounts `json:"ssl_writes,omitempty"`
	// ContentMethods is the state of each content method the capture was
	// configured with, by its name (N-39): requests and responses, each a
	// Content* value. ProbeCoverage.Content and Responses are active when
	// any configured method's are (N-42); MethodContent reads one method's.
	// Nil without content capture.
	// Net probe only.
	ContentMethods map[string]ContentMethodState `json:"content_methods,omitempty"`
}

// MethodContent is the request and response content state of one content
// method (N-42): the state the capture recorded for it, identity_only for a
// method it was not configured with, and, for a capture with no per-method
// record (written before N-39, or one without content capture), the probe's
// own Content and Responses, which a single-method capture's are.
func (p ProbeCoverage) MethodContent(method string) (requests, responses string) {
	if p.Diagnostics == nil || p.Diagnostics.ContentMethods == nil {
		return p.Content, p.Responses
	}
	m, ok := p.Diagnostics.ContentMethods[method]
	if !ok {
		return ContentIdentityOnly, ContentIdentityOnly
	}
	return m.Requests, m.Responses
}

// ContentMethodState is what one content method captured.
type ContentMethodState struct {
	Requests  string `json:"requests"`
	Responses string `json:"responses"`
}

// SSLWriteCounts compares, per SSL_write call of a tracked process, the
// length the caller asked to write with the value the call returned (N-36).
// A call that writes less than it was asked, or fails and is retried with
// the same bytes, put bytes in the stream twice while the content was copied
// at the call's entry; since N-37 it is copied at the return. Counted from
// the moment the SSL_write offset validated; a call that returned before
// that is not counted.
type SSLWriteCounts struct {
	Calls          uint64 `json:"calls"`           // calls whose return was seen
	Partial        uint64 `json:"partial"`         // returned 0 < ret < asked
	Failed         uint64 `json:"failed"`          // returned ret <= 0 (an error or a retry such as WANT_WRITE)
	BytesRequested uint64 `json:"bytes_requested"` // sum of the lengths asked
	BytesWritten   uint64 `json:"bytes_written"`   // sum of the positive returns
}

// RingStats describes one kernel ring buffer over a capture.
type RingStats struct {
	// SizeBytes is the ring's data size.
	SizeBytes uint64 `json:"size_bytes"`
	// PeakBytes is the highest occupancy userspace saw: at each record it
	// reads, the bytes committed or reserved and not yet consumed, the
	// record itself and its 8-byte header included. A lower bound on the
	// true peak, short of it by at most one record and its header.
	PeakBytes uint64 `json:"peak_bytes"`
	// Records counts the records userspace read from the ring.
	Records uint64 `json:"records"`
	// Drops counts the records the kernel discarded because the ring was
	// full; on ssl_events, write frames only. RingbufDrops is the sum of
	// Drops over the probe's rings.
	Drops uint64 `json:"drops"`
	// ReadDrops counts the SSL_read frames discarded because the ring was
	// full. Set on ssl_events only, nil elsewhere. Part of ResponseGaps.
	ReadDrops *uint64 `json:"read_drops,omitempty"`
}

// TrackedSetStats describes one eBPF object's tracked_pids map over a
// capture.
type TrackedSetStats struct {
	// Capacity is the map's maximum number of entries.
	Capacity uint32 `json:"capacity"`
	// Peak is the highest number of entries the map held, counted as the
	// kernel inserted them (P-34). When it equals Capacity, a further insert
	// failed and UntrackedChildren says so.
	Peak uint64 `json:"peak"`
	// AtStop is the number of entries the map held when the probe stopped.
	AtStop int64 `json:"at_stop"`
}

// NetContentCounts are the net probe's correlator counters for a capture.
// Connection counts are by connect; content counts by TLS connection (the
// process and its SSL object, N-30).
type NetContentCounts struct {
	Connections   int `json:"connections"`    // connections recorded at connect
	WithHostname  int `json:"with_hostname"`  // connections whose ClientHello named a host
	WithContent   int `json:"with_content"`   // HTTP/1.1 requests emitted as net_request
	Dials         int `json:"dials"`          // connections closed with no name and nothing written (N-22)
	AddressProbes int `json:"address_probes"` // connections to port 0, not emitted
	OpenAtStop    int `json:"open_at_stop"`   // connections still open at the stop (N-21)
	Replaced      int `json:"replaced"`       // connections replaced by a new connect on the same socket (N-24)
	// HellosFollowed counts ClientHellos followed across sends (N-31).
	HellosFollowed int `json:"hellos_followed"`
	DNS            int `json:"dns"`          // net_dns events (N-27)
	DNSNamed       int `json:"dns_named"`    // of those, the ones that carry the question
	DNSUnparsed    int `json:"dns_unparsed"` // sends to port 53 that did not parse as a query
	Datagrams      int `json:"datagrams"`    // addressed datagrams recorded (N-28)
	// ContentUnsupported counts the connections whose ClientHello offered h2
	// in ALPN, whatever the server chose.
	ContentUnsupported int `json:"content_unsupported"`
	// H2Preface counts the TLS connections whose request stream began with
	// the HTTP/2 client connection preface: h2 negotiated, seen in the
	// plaintext. Counted only while content capture is active.
	H2Preface int `json:"h2_preface"`
	// H2PrefaceUnvalidated counts the write frames that began with the
	// HTTP/2 preface while SSL_write offset validation was reading, before
	// content capture was active. Validation accepts HTTP/1.x only, so these
	// are h2 connections the content counts above miss.
	H2PrefaceUnvalidated int `json:"h2_preface_unvalidated"`
	// FramesH2 counts the write frames on connections counted in H2Preface.
	// None is parsed into a request.
	FramesH2 int `json:"frames_h2"`
	// FramesUnattributed counts write frames that yielded no request: they
	// did not parse as HTTP/1.1, had no host, or were truncated.
	FramesUnattributed int `json:"frames_unattributed"`
	// FramesTruncated counts write frames larger than the capture copies.
	FramesTruncated int `json:"frames_truncated"`
	// Responses and the counts after it are the response side (N-29).
	Responses             int    `json:"responses"`
	ResponsesUnpaired     int    `json:"responses_unpaired"`
	ResponsesUnattributed int    `json:"responses_unattributed"`
	ResponsesIncomplete   int    `json:"responses_incomplete"`
	ResponsesTruncated    int    `json:"responses_truncated"`
	ResponsesUnparsed     int    `json:"responses_unparsed"`
	SSEEvents             int    `json:"sse_events"`
	ReadsUnvalidated      int    `json:"reads_unvalidated"`
	ReadFaults            uint64 `json:"read_faults"`
	// WebSocket counts (N-41): request streams switched by an upgrade, 101
	// accepts, client messages emitted as net_request, server messages
	// counted into net_response turns, directions refused for an extension
	// or a compressed frame, directions ended by a malformed frame or
	// missing bytes.
	WebSockets       int `json:"websockets,omitempty"`
	WSAccepted       int `json:"ws_accepted,omitempty"`
	WSRequests       int `json:"ws_requests,omitempty"`
	WSServerMessages int `json:"ws_server_messages,omitempty"`
	// WSModelRequests counts the client messages that parsed as a
	// Responses API request and carry its digest (P-42).
	WSModelRequests int `json:"ws_model_requests,omitempty"`
	WSRefused       int `json:"ws_refused,omitempty"`
	// WSRefusedReasons counts the refused directions by the reason the
	// parser gave (N-43), at most 16 reasons, the rest under "(other)".
	WSRefusedReasons map[string]int `json:"ws_refused_reasons,omitempty"`
	// WSDeflate counts the accepts that agreed to permessage-deflate,
	// whose messages are decoded (N-43).
	WSDeflate  int `json:"ws_deflate,omitempty"`
	WSUnparsed int `json:"ws_unparsed,omitempty"`
	// rustls counts (tls-rustls-aead, N-39, N-40): frames discarded before
	// their direction validated, read frames with no socket, ignored
	// rebinds of an encrypter, encrypters whose socket had a state of its
	// own.
	AEADUnvalidated int `json:"aead_unvalidated,omitempty"`
	AEADUnbound     int `json:"aead_unbound,omitempty"`
	AEADRebound     int `json:"aead_rebound,omitempty"`
	AEADUnpaired    int `json:"aead_unpaired,omitempty"`
}

// Coverage is the per-probe loss record that travels with a ground truth file.
type Coverage struct {
	Schema int                      `json:"schema"`
	Probes map[string]ProbeCoverage `json:"probes"`
}

// GroundTruthFile is the on-disk form of a capture: the events plus the record
// of what the capture may have lost. A nil Coverage means unknown, which is
// not the same as complete.
type GroundTruthFile struct {
	Events   GroundTruth `json:"events"`
	Coverage *Coverage   `json:"coverage"`
	// RootPID is the agent process the capture was rooted at, the root of the
	// process forest the verifier builds (V1). Zero means the capture had
	// no root (legacy file, or host-wide recording), so no tree can be built
	// and the verifier cannot attribute events.
	RootPID uint32 `json:"root_pid,omitempty"`
	// Workspace is the absolute directory the capture watched. A harness
	// baseline names it with a placeholder, so a baseline measured in one
	// directory applies to a run in another. Empty means unknown.
	Workspace string `json:"workspace,omitempty"`
	// FSScope says which file events the capture can contain. Nil means the
	// capture predates the record: the fs probe then kept only paths under
	// Workspace, from any process.
	FSScope *FSScope `json:"fs_scope,omitempty"`
	// Sensitive is the snapshot of the harness's security-sensitive files at
	// the start and the stop of the capture (V-40). Nil means the capture
	// took none: it predates the record, or no adapter declared a file.
	Sensitive *SensitiveSnapshot `json:"sensitive,omitempty"`
}

// FSScope rules.
const (
	// FSScopeTreeOrWorkspace: every file event caused by the agent's process
	// tree, on any marked filesystem, plus events under Workspace from any
	// other process. A file claim is therefore always in scope.
	FSScopeTreeOrWorkspace = "tree-or-workspace"
	// FSScopeUnfiltered: every file event on the marked filesystems, from any
	// process. Written when the capture has no root pid to build a tree from.
	FSScopeUnfiltered = "unfiltered"
)

// FSScope records where the fs probe was looking and what watch kept, so the
// verifier can tell an event that did not happen from one that was outside
// the scope.
type FSScope struct {
	// Rule is one of the FSScope constants.
	Rule string `json:"rule"`
	// Mounts lists the mount points of the filesystems that were marked, one
	// per filesystem. An event on an unmarked filesystem is not observable.
	Mounts []string `json:"mounts"`
	// Unmarked lists the mount points the probe tried and could not mark,
	// with the error.
	Unmarked map[string]string `json:"unmarked,omitempty"`
	// DroppedOutside counts the file events watch left out under the rule:
	// events by processes outside the agent's tree on paths outside
	// Workspace.
	DroppedOutside int `json:"dropped_outside"`
	// Unresolved counts the file events whose path the probe could not
	// resolve at all, by action type: a delete inside a tree being removed,
	// whose parent directory was gone by the time the event was read. They
	// are not in Events, since an event with no target cannot be aligned or
	// attributed to a path; the count says the capture is missing them.
	Unresolved map[string]int `json:"unresolved,omitempty"`
	// Filesystems is the probe's mount table when the capture started,
	// every mount grouped by filesystem, so a path can be traced to the file
	// it reaches (P-33). Nil means not recorded: a capture before the record,
	// or a probe that could not read the table.
	Filesystems []FSMounts `json:"filesystems,omitempty"`
	// MountTableChanged says whether the probe's mount table changed while
	// the capture ran, which would make Filesystems stale. Nil means not
	// measured.
	MountTableChanged *bool `json:"mount_table_changed,omitempty"`
}

// ParseGroundTruthFile reads a ground truth file in either form: the current
// object with events and coverage, or the legacy bare array of events. A
// legacy array, or an object with no coverage, yields a nil Coverage.
//
// ParseGroundTruth, and a bare json.Unmarshal into GroundTruth, reject the
// object form on purpose, so a caller that ignores coverage fails loudly and
// does not silently drop it.
func ParseGroundTruthFile(data []byte) (GroundTruthFile, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return GroundTruthFile{}, fmt.Errorf("ground truth file is empty")
	}

	var f GroundTruthFile
	if trimmed[0] == '[' {
		events, err := ParseGroundTruth(trimmed)
		if err != nil {
			return GroundTruthFile{}, err
		}
		f.Events = events
		return f, nil
	}

	if err := json.Unmarshal(trimmed, &f); err != nil {
		return GroundTruthFile{}, err
	}
	for i := range f.Events {
		if err := f.Events[i].Validate(); err != nil {
			return GroundTruthFile{}, err
		}
	}
	if f.Coverage != nil && (f.Coverage.Schema < MinCoverageSchema || f.Coverage.Schema > CoverageSchema) {
		return GroundTruthFile{}, fmt.Errorf("unsupported coverage schema %d (this build reads %d to %d)", f.Coverage.Schema, MinCoverageSchema, CoverageSchema)
	}
	return f, nil
}
