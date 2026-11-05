package tlsoffset

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// bunSynth plants a Bun-like image: the ssl_lib.cc path in .rodata, the
// pinned SSL_write and SSL_read of bunBuilds[0] with the path's address
// filled in, and a caller of both. The options change one thing each.
type bunSynthOpts struct {
	noString   bool // the path absent
	tailString bool // the path only as the tail of a longer string
	flipByte   bool // one byte of SSL_write changed
	noRead     bool // SSL_read absent
	twoWrites  bool // SSL_write planted twice
	noCaller   bool // no call reaches the functions
	misalign   bool // SSL_write 8 bytes past its 64-byte slot, after a nop
}

func bunSynth(t *testing.T, o bunSynthOpts) (path string, write, read uint64) {
	t.Helper()
	s := newSynth()
	s.str("unrelated")
	var str uint64
	switch {
	case o.noString:
		str = s.str("../../vendor/boringssl/ssl/ssl_cipher.cc")
	case o.tailString:
		str = s.str("x"+bunSSLLibPath) + 1
	default:
		str = s.str(bunSSLLibPath)
	}
	code := func(h string) []byte {
		b, err := bunCode(h, uint32(str))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	s.fn(0x55, 0xc3) // the first function, so that every pinned one has padding before it
	w := code(bunBuilds[0].write)
	if o.flipByte {
		w[len(w)/2] ^= 0x01
	}
	if o.misalign {
		s.fn(0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xcc)
		write = s.at()
		s.bytes(w...)
	} else {
		write = s.fn(w...)
	}
	if o.twoWrites {
		s.fn(w...)
	}
	if !o.noRead {
		read = s.fn(code(bunBuilds[0].read)...)
	}
	if !o.noCaller {
		s.fn(0x55)
		s.branch(0xe8, write)
		if read != 0 {
			s.branch(0xe8, read)
		}
		s.bytes(0xc3)
	}
	return s.write(t), write, read
}

func TestScanBunBoringSSL_Synthetic(t *testing.T) {
	defer func(n int) { scanChunk = n }(scanChunk)
	scanChunk = 512 // windows smaller than the functions, so matches span them

	path, w, r := bunSynth(t, bunSynthOpts{})
	res, err := ScanBunBoringSSL(path)
	if err != nil {
		t.Fatalf("ScanBunBoringSSL: %v", err)
	}
	if res.Build != bunBuilds[0].name || len(res.Write) != 1 || len(res.Read) != 1 || res.Write[0].VA != w || res.Read[0].VA != r {
		t.Fatalf("got %+v, want SSL_write %#x and SSL_read %#x of %s", res, w, r, bunBuilds[0].name)
	}
	if res.Write[0].FileOff != w || res.Read[0].FileOff != r {
		t.Errorf("file offsets %#x, %#x; the synthetic image maps addresses to equal offsets", res.Write[0].FileOff, res.Read[0].FileOff)
	}

	for _, tc := range []struct {
		name string
		o    bunSynthOpts
		want string
	}{
		{"no ssl_lib.cc path", bunSynthOpts{noString: true}, "starts 0 strings"},
		{"path only as a tail", bunSynthOpts{tailString: true}, "starts 0 strings"},
		{"one byte differs", bunSynthOpts{flipByte: true}, "found 0 times"},
		{"SSL_read absent", bunSynthOpts{noRead: true}, "found 1 times and SSL_read's 0"},
		{"SSL_write twice", bunSynthOpts{twoWrites: true}, "found 2 times"},
		{"no caller", bunSynthOpts{noCaller: true}, "no direct call"},
		{"not after padding", bunSynthOpts{misalign: true}, "not 16-byte aligned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, _, _ := bunSynth(t, tc.o)
			_, err := ScanBunBoringSSL(path)
			if !errors.Is(err, ErrNoAnchor) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want ErrNoAnchor with %q", err, tc.want)
			}
		})
	}
}

// TestScanBunBoringSSL_TwoBuildsMatch: two entries whose bytes both occur
// are refused rather than one chosen.
func TestScanBunBoringSSL_TwoBuildsMatch(t *testing.T) {
	defer func(b []bunBuild) { bunBuilds = b }(bunBuilds)
	bunBuilds = append(bunBuilds[:1:1], bunBuild{name: "copy", write: bunBuilds[0].write, read: bunBuilds[0].read})
	path, _, _ := bunSynth(t, bunSynthOpts{})
	if _, err := ScanBunBoringSSL(path); !errors.Is(err, ErrNoAnchor) || !strings.Contains(err.Error(), "several Bun builds") {
		t.Errorf("err = %v, want ErrNoAnchor naming several builds", err)
	}
}

// TestScanBunBoringSSL_PinnedBytesParse: every entry decodes, names the
// string at least once in each function, and holds no other placeholder.
func TestScanBunBoringSSL_PinnedBytesParse(t *testing.T) {
	for _, b := range bunBuilds {
		for _, h := range []string{b.write, b.read} {
			if !strings.Contains(h, bunStringField) {
				t.Errorf("%s: a function without the string field", b.name)
			}
			if _, err := bunCode(h, 0x12345678); err != nil {
				t.Errorf("%s: %v", b.name, err)
			}
		}
	}
}

// TestScanBunBoringSSL_OpenCode is the locator test against the real
// binary: on the OpenCode 1.19.5 executable AGENT_TRACE_LOCATOR_BUN_BIN
// names (opencode-linux-x64/bin/opencode, Bun 1.4.4; skipped without it),
// the pinned build is found at the addresses the static study identified,
// with their file offsets. TestLocators_ExternalBinary logs what the
// locator says of any other executable (Claude Code's Bun and the musl
// OpenCode build are refused).
func TestScanBunBoringSSL_OpenCode(t *testing.T) {
	path := os.Getenv("AGENT_TRACE_LOCATOR_BUN_BIN")
	if path == "" {
		t.Skip("AGENT_TRACE_LOCATOR_BUN_BIN not set")
	}
	res, err := ScanBunBoringSSL(path)
	if err != nil {
		t.Fatalf("ScanBunBoringSSL: %v", err)
	}
	t.Logf("build id %s, %s", res.BuildID, res.Build)
	want := []struct {
		name    string
		c       []Candidate
		va, off uint64
	}{
		{"SSL_write", res.Write, 0x28fd5c0, 0x26f55c0},
		{"SSL_read", res.Read, 0x28673b0, 0x265f3b0},
	}
	for _, w := range want {
		if len(w.c) != 1 || w.c[0].VA != w.va || w.c[0].FileOff != w.off {
			t.Errorf("%s = %+v, want VA %#x file offset %#x", w.name, w.c, w.va, w.off)
		}
	}
}
