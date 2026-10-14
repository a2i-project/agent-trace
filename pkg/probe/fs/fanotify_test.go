package fs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"golang.org/x/sys/unix"
)

// Helper to build a fanotify metadata header
func buildMetadata(mask uint64, pid int32, infoLen uint16) []byte {
	buf := make([]byte, metadataSize)
	eventLen := uint32(metadataSize) + uint32(infoLen)
	binary.LittleEndian.PutUint32(buf[0:4], eventLen)
	buf[4] = 3 // Vers
	buf[5] = 0 // Reserved
	binary.LittleEndian.PutUint16(buf[6:8], metadataSize)
	binary.LittleEndian.PutUint64(buf[8:16], mask)
	fdcwd := int32(unix.AT_FDCWD)
	binary.LittleEndian.PutUint32(buf[16:20], uint32(fdcwd))
	binary.LittleEndian.PutUint32(buf[20:24], uint32(pid))
	return buf
}

func buildDfidNameInfo(handleType int32, handleData []byte, name string) []byte {
	nameBytes := []byte(name + "\x00")
	infoLen := 20 + len(handleData) + len(nameBytes)

	// pad to 4 bytes boundary
	padding := (4 - (infoLen % 4)) % 4
	infoLen += padding

	buf := make([]byte, infoLen)
	buf[0] = fanEventInfoTypeDfidName
	buf[1] = 0 // pad
	binary.LittleEndian.PutUint16(buf[2:4], uint16(infoLen))

	// fsid is 8 bytes, leave as 0
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(handleData)))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(handleType))

	copy(buf[20:], handleData)
	copy(buf[20+len(handleData):], nameBytes)

	return buf
}

func buildFidInfo(handleType int32, handleData []byte) []byte {
	infoLen := 20 + len(handleData)
	padding := (4 - (infoLen % 4)) % 4
	infoLen += padding

	buf := make([]byte, infoLen)
	buf[0] = fanEventInfoTypeFid
	buf[1] = 0
	binary.LittleEndian.PutUint16(buf[2:4], uint16(infoLen))

	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(handleData)))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(handleType))
	copy(buf[20:], handleData)

	return buf
}

func buildDfidInfo(handleType int32, handleData []byte) []byte {
	// Dfid has the same structure as Fid but type is 3
	buf := buildFidInfo(handleType, handleData)
	buf[0] = fanEventInfoTypeDfid
	return buf
}

func mockResolver(_ fsID, handleType int32, handleData []byte) string {
	if handleType == 1 {
		str := string(handleData)
		if str == "dir123" {
			return "/mock/dir"
		}
		if str == "file123" {
			return "/mock/file.txt"
		}
	}
	return ""
}

func TestParseEvents_DfidName(t *testing.T) {
	infoBuf := buildDfidNameInfo(1, []byte("dir123"), "test.txt")
	metaBuf := buildMetadata(unix.FAN_CREATE, 1234, uint16(len(infoBuf)))

	var buf bytes.Buffer
	buf.Write(metaBuf)
	buf.Write(infoBuf)

	events := parseEvents(buf.Bytes(), buf.Len(), mockResolver)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Mask != unix.FAN_CREATE {
		t.Errorf("expected mask %x, got %x", unix.FAN_CREATE, events[0].Mask)
	}
	if events[0].PID != 1234 {
		t.Errorf("expected pid 1234, got %d", events[0].PID)
	}
	if events[0].Path != "/mock/dir/test.txt" {
		t.Errorf("expected path /mock/dir/test.txt, got %q", events[0].Path)
	}
	if events[0].Ambiguous {
		t.Error("DFID_NAME resolution should not be ambiguous")
	}
}

func TestParseEvents_Fid(t *testing.T) {
	infoBuf := buildFidInfo(1, []byte("file123"))
	metaBuf := buildMetadata(unix.FAN_MODIFY, 9999, uint16(len(infoBuf)))

	var buf bytes.Buffer
	buf.Write(metaBuf)
	buf.Write(infoBuf)

	events := parseEvents(buf.Bytes(), buf.Len(), mockResolver)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Path != "/mock/file.txt" {
		t.Errorf("expected path /mock/file.txt, got %q", events[0].Path)
	}
	if events[0].Ambiguous {
		t.Error("FID resolution should not be ambiguous")
	}
}

func TestParseEvents_DfidOnly(t *testing.T) {
	infoBuf := buildDfidInfo(1, []byte("dir123"))
	metaBuf := buildMetadata(unix.FAN_DELETE, 4444, uint16(len(infoBuf)))

	var buf bytes.Buffer
	buf.Write(metaBuf)
	buf.Write(infoBuf)

	events := parseEvents(buf.Bytes(), buf.Len(), mockResolver)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Path != "/mock/dir" {
		t.Errorf("expected path /mock/dir, got %q", events[0].Path)
	}
	if !events[0].Ambiguous {
		t.Error("DFID-only resolution (no filename) should be ambiguous")
	}
}

func TestParseEvents_Overflow(t *testing.T) {
	metaBuf := buildMetadata(unix.FAN_Q_OVERFLOW, 0, 0)

	events := parseEvents(metaBuf, len(metaBuf), mockResolver)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Mask != unix.FAN_Q_OVERFLOW {
		t.Errorf("expected overflow mask")
	}
}

func TestObserver_ProcessRawEvent(t *testing.T) {
	obs := &Observer{
		events: make(chan models.GroundTruthEvent, 10),
		cfg: Config{
			PathFilter: "/mock",
			PIDFilter:  1234,
		},
	}

	now := time.Now()

	// Should pass filters and emit event
	obs.processRawEvent(&rawEvent{
		Mask: unix.FAN_CREATE,
		PID:  1234,
		Path: "/mock/dir/file.txt",
	}, now)

	// Should be filtered out by PID
	obs.processRawEvent(&rawEvent{
		Mask: unix.FAN_CREATE,
		PID:  9999,
		Path: "/mock/dir/file2.txt",
	}, now)

	// Should be filtered out by Path
	obs.processRawEvent(&rawEvent{
		Mask: unix.FAN_CREATE,
		PID:  1234,
		Path: "/other/dir/file3.txt",
	}, now)

	// Should flag overflow
	obs.processRawEvent(&rawEvent{
		Mask: unix.FAN_Q_OVERFLOW,
	}, now)

	close(obs.events)

	var emitted []models.GroundTruthEvent
	for e := range obs.events {
		emitted = append(emitted, e)
	}

	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}
	if emitted[0].Target != "/mock/dir/file.txt" {
		t.Errorf("unexpected target %q", emitted[0].Target)
	}
	if !obs.Overflow() {
		t.Errorf("expected overflow to be set")
	}
}

// One operation can reach the probe as one merged notification or as several,
// depending on whether anything read between them. The emitted sequence must
// not depend on that: a repeated write-class or rename event on one path by
// one process is one event, and anything else on the path resets it (P-18).
func TestProcessRawEvent_RepeatedWritesAndRenamesCollapse(t *testing.T) {
	obs := &Observer{events: make(chan models.GroundTruthEvent, 32), cfg: Config{PathFilter: "/mock"}}
	now := time.Now()
	raws := []rawEvent{
		{Mask: unix.FAN_MODIFY, PID: 1, Path: "/mock/a"},                         // the truncating open
		{Mask: unix.FAN_MODIFY, PID: 1, Path: "/mock/a"},                         // the write: same operation
		{Mask: unix.FAN_MODIFY, PID: 1, Path: "/mock/b"},                         // another path
		{Mask: unix.FAN_MODIFY, PID: 1, Path: "/mock/a"},                         // a changed, b between: still a's run
		{Mask: unix.FAN_MODIFY, PID: 2, Path: "/mock/a"},                         // another process: emitted
		{Mask: unix.FAN_OPEN, PID: 1, Path: "/mock/a"},                           // resets a
		{Mask: unix.FAN_MODIFY, PID: 1, Path: "/mock/a"},                         // emitted again
		{Mask: unix.FAN_MOVED_FROM, PID: 1, Path: "/mock"},                       // one rename, two directory-only records (before P-25)
		{Mask: unix.FAN_MOVED_TO, PID: 1, Path: "/mock"},                         //
		{Mask: unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO, PID: 1, Path: "/mock/d"}, // merged: one event
	}
	for i := range raws {
		obs.processRawEvent(&raws[i], now.Add(time.Duration(i)))
	}
	close(obs.events)
	var got []string
	for e := range obs.events {
		got = append(got, fmt.Sprintf("%s %s %d", e.ActionType, e.Target, e.PID))
	}
	want := []string{
		"file_write /mock/a 1",
		"file_write /mock/b 1",
		"file_write /mock/a 2",
		"file_open /mock/a 1",
		"file_write /mock/a 1",
		"file_rename /mock 1",
		"file_rename /mock/d 1",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("emitted:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A record no handle resolved is counted once per action type, before the
// path filter it cannot pass; the observer's own records are not counted.
func TestProcessRawEvent_CountsUnresolvedPaths(t *testing.T) {
	obs := &Observer{events: make(chan models.GroundTruthEvent, 8), cfg: Config{PathFilter: "/mock"}}
	raws := []rawEvent{
		{Mask: unix.FAN_DELETE, PID: 7},
		{Mask: unix.FAN_MOVED_FROM | unix.FAN_CREATE, PID: 7},
		{Mask: unix.FAN_DELETE, PID: int32(os.Getpid())},
		{Mask: unix.FAN_DELETE, PID: 7, Path: "/mock/d"},
	}
	for i := range raws {
		obs.processRawEvent(&raws[i], time.Now())
	}
	if got := obs.CaptureCoverage().UnresolvedPaths; got != 3 {
		t.Errorf("UnresolvedPaths = %d, want 3", got)
	}
}

// A DFID_NAME record whose directory does not resolve yields no path, not the
// bare entry name: the event then resolves through its FID record when there
// is one, and otherwise has no path and is counted as unresolved.
func TestParseEvents_DfidNameWithUnresolvedDirectory(t *testing.T) {
	tests := []struct {
		name string
		info [][]byte
		want string
	}{
		{name: "no other record", info: [][]byte{buildDfidNameInfo(1, []byte("gone"), "leaf.txt")}, want: ""},
		{name: "a FID record resolves", info: [][]byte{buildDfidNameInfo(1, []byte("gone"), "leaf.txt"), buildFidInfo(1, []byte("file123"))}, want: "/mock/file.txt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var info []byte
			for _, r := range tc.info {
				info = append(info, r...)
			}
			buf := append(buildMetadata(unix.FAN_DELETE, 1, uint16(len(info))), info...)
			events := parseEvents(buf, len(buf), mockResolver)
			if len(events) != 1 || events[0].Path != tc.want {
				t.Fatalf("events = %+v, want one with path %q", events, tc.want)
			}
		})
	}
}

// The timestamps the real read path gives a batch: one clock reading for the
// batch and one nanosecond per record on top, so the records keep the kernel's
// order under a stable sort by time (P-18). The records go through
// drainNonBlocking from a pipe, not through processRawEvent directly.
func TestDrainNonBlocking_StampsRecordsByBatchPosition(t *testing.T) {
	obs, records, _ := pipeObserver(t)
	queueRecords(t, records, unix.FAN_MODIFY, 101, 102, 103, 104)
	before := time.Now()
	obs.drainNonBlocking(make([]byte, 4096))
	close(obs.events)
	var got []models.GroundTruthEvent
	for e := range obs.events {
		got = append(got, e)
	}
	if len(got) != 4 {
		t.Fatalf("emitted %d events, want 4", len(got))
	}
	if got[0].Timestamp.Before(before) {
		t.Errorf("first stamp %v precedes the read", got[0].Timestamp)
	}
	for i := 1; i < len(got); i++ {
		if d := got[i].Timestamp.Sub(got[i-1].Timestamp); d != time.Nanosecond {
			t.Errorf("record %d is %v after record %d, want 1ns", i, d, i-1)
		}
		if got[i].PID != uint32(101+i) {
			t.Errorf("record %d has pid %d, want %d: kernel order lost", i, got[i].PID, 101+i)
		}
	}
}
