package fs

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"golang.org/x/sys/unix"
)

// The probe asks for the entry's name (P-25): FAN_REPORT_FID plus
// FAN_REPORT_DFID_NAME, 0xe00. The flags it used before, 0x2400, were
// FAN_REPORT_DIR_FID | FAN_REPORT_FD_ERROR: no name, and a bit kernels before
// 6.13 do not know.
func TestReportFlagsRequestEntryNames(t *testing.T) {
	if reportFlags != 0xe00 {
		t.Errorf("reportFlags = %#x, want 0xe00", reportFlags)
	}
	for _, f := range []struct {
		bit  uint
		name string
		want bool
	}{
		{unix.FAN_REPORT_FID, "FAN_REPORT_FID", true},
		{unix.FAN_REPORT_DIR_FID, "FAN_REPORT_DIR_FID", true},
		{unix.FAN_REPORT_NAME, "FAN_REPORT_NAME", true},
		{unix.FAN_REPORT_FD_ERROR, "FAN_REPORT_FD_ERROR", false},
		{unix.FAN_REPORT_TARGET_FID, "FAN_REPORT_TARGET_FID", false},
	} {
		if got := reportFlags&f.bit != 0; got != f.want {
			t.Errorf("%s set = %v, want %v", f.name, got, f.want)
		}
	}
}

// A content record carries the directory with the entry's name as it was
// when the event happened, and the file's own handle, which resolves to
// wherever the file is when the record is read. The name wins, so the close
// of a temporary renamed before the read still names the temporary.
func TestParseEvents_ContentRecordNamesTheEntryAsItWasNamed(t *testing.T) {
	info := append(buildDfidNameInfo(1, []byte("dir123"), "notes.txt.tmp.1.0123456789ab"), buildFidInfo(1, []byte("file123"))...)
	buf := append(buildMetadata(unix.FAN_CLOSE_WRITE, 1, uint16(len(info))), info...)
	events := parseEvents(buf, len(buf), mockResolver)
	if len(events) != 1 || events[0].Path != "/mock/dir/notes.txt.tmp.1.0123456789ab" || events[0].Ambiguous {
		t.Fatalf("events = %+v, want the temporary's name, not ambiguous", events)
	}
	if string(events[0].HandleData) != "file123" {
		t.Errorf("the FID handle is kept for the inode lookups: %q", events[0].HandleData)
	}
}

// What the named records become (P-25, P-18): a rename is two events, its
// source and its destination; a create merged with the rename of its name
// (a temporary renamed away before the read) is the write then the rename; a
// rename away and back is one event per name whether or not the kernel merged
// the records; two renames onto one name with nothing on it between are one
// event, as the kernel's merge of the second into the first gives.
func TestProcessRawEvent_NamedRenames(t *testing.T) {
	for _, c := range []struct {
		name string
		raws []rawEvent
		want []string
	}{
		{"one rename", []rawEvent{
			{Mask: unix.FAN_MOVED_FROM, PID: 1, Path: "/mock/a"},
			{Mask: unix.FAN_MOVED_TO, PID: 1, Path: "/mock/sub/b"},
		}, []string{"file_rename /mock/a", "file_rename /mock/sub/b"}},
		{"a temporary renamed before the read", []rawEvent{
			{Mask: unix.FAN_CREATE | unix.FAN_MOVED_FROM, PID: 1, Path: "/mock/t.tmp"},
			{Mask: unix.FAN_MOVED_TO, PID: 1, Path: "/mock/t"},
		}, []string{"file_write /mock/t.tmp", "file_rename /mock/t.tmp", "file_rename /mock/t"}},
		{"away and back, merged", []rawEvent{
			{Mask: unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO, PID: 1, Path: "/mock/i"},
			{Mask: unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO, PID: 1, Path: "/mock/i2"},
		}, []string{"file_rename /mock/i", "file_rename /mock/i2"}},
		{"away and back, apart", []rawEvent{
			{Mask: unix.FAN_MOVED_FROM, PID: 1, Path: "/mock/i"},
			{Mask: unix.FAN_MOVED_TO, PID: 1, Path: "/mock/i2"},
			{Mask: unix.FAN_MOVED_FROM, PID: 1, Path: "/mock/i2"},
			{Mask: unix.FAN_MOVED_TO, PID: 1, Path: "/mock/i"},
		}, []string{"file_rename /mock/i", "file_rename /mock/i2"}},
		{"two renames onto one name", []rawEvent{
			{Mask: unix.FAN_MOVED_FROM, PID: 1, Path: "/mock/a"},
			{Mask: unix.FAN_MOVED_TO, PID: 1, Path: "/mock/x"},
			{Mask: unix.FAN_MOVED_FROM, PID: 1, Path: "/mock/b"},
			{Mask: unix.FAN_MOVED_TO, PID: 1, Path: "/mock/x"},
		}, []string{"file_rename /mock/a", "file_rename /mock/x", "file_rename /mock/b"}},
		{"two renames onto one name, an open between", []rawEvent{
			{Mask: unix.FAN_MOVED_TO, PID: 1, Path: "/mock/x"},
			{Mask: unix.FAN_OPEN, PID: 1, Path: "/mock/x"},
			{Mask: unix.FAN_MOVED_TO, PID: 1, Path: "/mock/x"},
		}, []string{"file_rename /mock/x", "file_open /mock/x", "file_rename /mock/x"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			obs := &Observer{events: make(chan models.GroundTruthEvent, 16), cfg: Config{PathFilter: "/mock"}, mountFD: -1}
			for i := range c.raws {
				obs.processRawEvent(&c.raws[i], time.Now())
			}
			close(obs.events)
			var got []string
			for e := range obs.events {
				if e.PathIsAmbiguous {
					t.Errorf("%s %s is ambiguous", e.ActionType, e.Target)
				}
				got = append(got, fmt.Sprintf("%s %s", e.ActionType, e.Target))
			}
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("emitted %v, want %v", got, c.want)
			}
		})
	}
}

// The records the kernel sends with the probe's flags, on a real kernel. An
// unprivileged group may use these flags with an inode mark (Linux 5.13 and
// later), so this runs without root; the filesystem-wide mark the probe uses
// needs root, and the privileged tests check it. The directory's handle is
// resolved by name_to_handle_at, since open_by_handle_at needs privilege.
func TestKernelNamesEveryDirectoryEntryRecord(t *testing.T) {
	fd, err := unix.FanotifyInit(uint(unix.FAN_CLASS_NOTIF|reportFlags|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK), unix.O_RDONLY)
	if err != nil {
		t.Skipf("fanotify_init with the probe's flags: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	dir := t.TempDir()
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, watchMask|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, dir); err != nil {
		t.Skipf("fanotify_mark: %v", err)
	}
	dirHandle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, dir, 0)
	if err != nil {
		t.Skipf("name_to_handle_at: %v", err)
	}
	resolve := func(_ fsID, handleType int32, handleData []byte) string {
		if handleType == dirHandle.Type() && bytes.Equal(handleData, dirHandle.Bytes()) {
			return dir
		}
		return ""
	}
	p := func(name string) string { return filepath.Join(dir, name) }

	var raws []rawEvent
	read := func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := unix.Read(fd, buf)
			if errors.Is(err, unix.EAGAIN) || n <= 0 {
				return
			}
			raws = append(raws, parseEvents(buf, n, resolve)...)
		}
	}
	// Each step is read before the next, as the probe's read loop does.
	steps := []func() error{
		func() error { return os.WriteFile(p("a.txt"), []byte("a"), 0o644) },
		func() error { return os.Rename(p("a.txt"), p("b.txt")) },
		func() error { return os.WriteFile(p("b.txt.tmp.1.0123456789ab"), []byte("b"), 0o644) },
		func() error { return os.Rename(p("b.txt.tmp.1.0123456789ab"), p("b.txt")) },
		func() error { return os.Remove(p("b.txt")) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			t.Fatal(err)
		}
		read()
	}

	var got []string
	for _, r := range raws {
		if r.Ambiguous {
			t.Errorf("record %#x resolved ambiguously to %q", r.Mask, r.Path)
		}
		if r.Mask&(unix.FAN_CREATE|unix.FAN_DELETE|unix.FAN_MOVED_FROM|unix.FAN_MOVED_TO) == 0 {
			continue
		}
		var bits []string
		for _, b := range []struct {
			m uint64
			n string
		}{{unix.FAN_CREATE, "create"}, {unix.FAN_DELETE, "delete"}, {unix.FAN_MOVED_FROM, "moved_from"}, {unix.FAN_MOVED_TO, "moved_to"}} {
			if r.Mask&b.m != 0 {
				bits = append(bits, b.n)
			}
		}
		got = append(got, strings.Join(bits, "+")+" "+strings.TrimPrefix(r.Path, dir+"/"))
	}
	want := []string{
		"create a.txt", "moved_from a.txt", "moved_to b.txt",
		"create b.txt.tmp.1.0123456789ab", "moved_from b.txt.tmp.1.0123456789ab", "moved_to b.txt",
		"delete b.txt",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("directory-entry records:\n  got  %v\n  want %v", got, want)
	}
	t.Logf("dir handle %s, %d records", hex.EncodeToString(dirHandle.Bytes()), len(raws))
}
