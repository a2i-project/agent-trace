package fs

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
		{Mask: unix.FAN_MOVED_FROM, PID: 1, Path: "/mock"},                       // one rename, two notifications
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
