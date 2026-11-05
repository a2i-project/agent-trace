package tlsoffset

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// The locator of the content method tls-bun-boringssl (N-51): BoringSSL's
// SSL_write and SSL_read in a Bun executable, linked statically, stripped
// of their symbols and with no unwind table, found by their exact bytes as
// one known Bun build compiled them. A build whose bytes differ is not
// guessed at: the method refuses it, and a new build gets its own entry.

// bunSSLLibPath is the __FILE__ BoringSSL's error macro stores in Bun's
// builds, the anchor every pinned function's error calls name.
const bunSSLLibPath = "../../vendor/boringssl/ssl/ssl_lib.cc"

// bunStringField marks, in a pinned function's hex, the four bytes of an
// immediate that holds the address of bunSSLLibPath.
const bunStringField = "SSSSSSSS"

// bunBuild is one Bun build whose SSL_write and SSL_read the locator knows:
// the whole function, from its first byte to the last before the int3
// padding, in hex, with bunStringField for the string's address. Every
// other byte is pinned, call displacements included, so the entry matches
// that build's code and no other.
type bunBuild struct {
	name        string
	write, read string
}

// bunBuilds lists the known builds. Bun 1.4.4 is the runtime of OpenCode
// 1.19.5 (opencode-linux-x64 and opencode-linux-x64-baseline, one file):
// SSL_write at 0x28fd5c0 and SSL_read, with SSL_peek inlined, at 0x28673b0.
// The functions were identified by the error-line immediates their
// OPENSSL_PUT_ERROR calls pass (lines 955, 960, 975 and 981 of ssl_lib.cc
// for SSL_write; 933 for SSL_peek, whose ssl_read_impl SSL_read calls) at
// the BoringSSL commit Bun 1.4.4 pins, and their callers are uSockets'
// us_internal_ssl_writev and us_internal_ssl_on_data and the three
// instances of Bun's SSLWrapper.
var bunBuilds = []bunBuild{{
	name: "Bun 1.4.4 (38afee6c8), BoringSSL 41bf9b59",
	write: "554889e54157415641554154534883ec184189d74989f64889fb488b4730c780" +
		"c400000000000000e83392a9ffe8ae65f303c700000000004883bb9800000000" +
		"7430b9SSSSSSSSbf1000000031f6ba4200000041b8bb030000e87227bbffb8ff" +
		"ffffff4883c4185b415c415d415e415f5dc348837b28000f848a00000048c745" +
		"c800000000c645d7004585ff0f88a10000004589ff4c8d65d74c8d6dc8eb1c90" +
		"488b034889df4c89e64c89ea4c89f14d89f8ff5048807dd7007468488b433048" +
		"8b80180100004885c074d50fb78080080000a90820000075c74889dfe89fe9f4" +
		"ff85c00f887affffff75b5b9SSSSSSSSbf1000000031f6bad700000041b8cf03" +
		"0000e952ffffffb9SSSSSSSSbf1000000031f6bae200000041b8c0030000e936" +
		"ffffff85c00f8e38ffffff8b45c8e930ffffff488b4330488b80180100004885" +
		"c0740e0fb78080080000a908200000741cb9SSSSSSSSbf1000000031f6ba6f00" +
		"000041b8d5030000e9ecfeffff4889dfe80be9f4ff85c00f88e6feffff75d2e9" +
		"67ffffff",
	read: "554889e54157415653504883bf9800000000742eb9SSSSSSSSbf1000000031f6" +
		"ba4200000041b8a5030000e8b089c4ffbbffffffff89d84883c4085b415e415f" +
		"5dc389d34989f64989ffe8b100000085c00f8e9100000085db7eda498b473048" +
		"8b888800000089db4839d9480f42d94885c9747b488bb0800000004c89f74889" +
		"daff1569aefe03498b4730488b88880000004829d9725f480198800000004889" +
		"8888000000498b47304883b8880000000075826683785a000f8577ffffff4c8d" +
		"7050488b78504883c05e4839c77405e86cc11eff49c746060000000049c70600" +
		"000000e94dffffff89c3e946ffffff31dbe93fffffffe825c6fc03",
}}

// bunCode returns a pinned function's bytes with the string's address
// filled in.
func bunCode(h string, str uint32) ([]byte, error) {
	var field [4]byte
	binary.LittleEndian.PutUint32(field[:], str)
	return hex.DecodeString(strings.ReplaceAll(h, bunStringField, hex.EncodeToString(field[:])))
}

// ScanBunBoringSSL finds SSL_write and SSL_read in a Bun executable for the
// content method tls-bun-boringssl (N-51):
//
//  1. bunSSLLibPath, NUL-terminated and starting a string, exactly once in
//     .rodata, at an address an imm32 can hold.
//  2. For each known build, its two functions with that address filled in,
//     searched in .text. A build counts only when each function occurs
//     exactly once; one function without the other, a second occurrence,
//     or two builds matching is refused.
//  3. Each match must be a function entry: 16-byte aligned, after an int3
//     padding byte, inside an executable segment, and the target of at
//     least one direct call. Bun has no .eh_frame_hdr, so these replace
//     the unwind table the other locators use.
//
// The result holds one candidate per function, scored 100, and the build's
// name in Build. ErrNoAnchor whenever a step fails: a configured method
// whose bytes do not match exactly loads no probe.
func ScanBunBoringSSL(path string) (Result, error) {
	f, err := elf.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("open elf: %w", err)
	}
	defer func() { _ = f.Close() }()
	res := Result{BuildID: getBuildID(f)}
	im := &image{f: f, text: f.Section(".text"), rodata: f.Section(".rodata")}
	if im.text == nil || im.rodata == nil {
		return res, fmt.Errorf("%w: no .text or .rodata section", ErrNoAnchor)
	}
	str, err := im.bunString()
	if err != nil {
		return res, err
	}

	type pinned struct {
		build       bunBuild
		write, read []byte
	}
	var builds []pinned
	var pats [][]byte
	for _, b := range bunBuilds {
		w, err := bunCode(b.write, str)
		if err != nil {
			return res, fmt.Errorf("pinned bytes of %s: %w", b.name, err)
		}
		r, err := bunCode(b.read, str)
		if err != nil {
			return res, fmt.Errorf("pinned bytes of %s: %w", b.name, err)
		}
		builds = append(builds, pinned{b, w, r})
		pats = append(pats, w, r)
	}
	hits, err := im.findExact(pats)
	if err != nil {
		return res, err
	}

	var found []string
	for i, b := range builds {
		w, r := hits[2*i], hits[2*i+1]
		if len(w) == 0 && len(r) == 0 {
			continue
		}
		if len(w) != 1 || len(r) != 1 {
			return res, fmt.Errorf("%w: %s: SSL_write's bytes found %d times and SSL_read's %d times, need each once", ErrNoAnchor, b.build.name, len(w), len(r))
		}
		found = append(found, b.build.name)
		res.Build = b.build.name
		res.Write = []Candidate{{VA: w[0], FileOff: vaToFileOff(f, w[0]), Score: 100}}
		res.Read = []Candidate{{VA: r[0], FileOff: vaToFileOff(f, r[0]), Score: 100}}
	}
	switch len(found) {
	case 0:
		return res, fmt.Errorf("%w: no known Bun build's SSL_write and SSL_read bytes (known: %s)", ErrNoAnchor, bunBuildNames())
	case 1:
	default:
		return res, fmt.Errorf("%w: the bytes of several Bun builds match (%s)", ErrNoAnchor, strings.Join(found, "; "))
	}

	entries := map[uint64]bool{res.Write[0].VA: true, res.Read[0].VA: true}
	calls, err := im.branchRefs(entries)
	if err != nil {
		return res, err
	}
	called := map[uint64]bool{}
	for _, c := range calls {
		if c.op == 0xe8 {
			called[c.target] = true
		}
	}
	for _, fn := range []struct {
		name string
		va   uint64
	}{{"SSL_write", res.Write[0].VA}, {"SSL_read", res.Read[0].VA}} {
		if err := im.bunEntry(fn.va, called[fn.va]); err != nil {
			return res, fmt.Errorf("%w: %s at %#x: %v", ErrNoAnchor, fn.name, fn.va, err)
		}
	}
	return res, nil
}

func bunBuildNames() string {
	var n []string
	for _, b := range bunBuilds {
		n = append(n, b.name)
	}
	return strings.Join(n, "; ")
}

// bunString returns the address of bunSSLLibPath: one occurrence in
// .rodata followed by a NUL and preceded by one (a string of its own, not
// the tail of a longer one), below 4 GiB.
func (im *image) bunString() (uint32, error) {
	at, err := im.stringsAt(bunSSLLibPath)
	if err != nil {
		return 0, err
	}
	var starts []uint64
	for _, va := range at[bunSSLLibPath] {
		if va == im.rodata.Addr {
			starts = append(starts, va)
			continue
		}
		b, err := im.readVA(va-1, 1)
		if err == nil && b[0] == 0 {
			starts = append(starts, va)
		}
	}
	if len(starts) != 1 {
		return 0, fmt.Errorf("%w: %q starts %d strings in .rodata, need one", ErrNoAnchor, bunSSLLibPath, len(starts))
	}
	if starts[0] > 0xffffffff {
		return 0, fmt.Errorf("%w: %q at %#x, above what an imm32 holds", ErrNoAnchor, bunSSLLibPath, starts[0])
	}
	return uint32(starts[0]), nil
}

// findExact returns, for each pattern, the address of every occurrence in
// .text, reading the section in windows that overlap by the longest
// pattern less one byte (N-35).
func (im *image) findExact(pats [][]byte) ([][]uint64, error) {
	longest := 0
	for _, p := range pats {
		longest = max(longest, len(p))
	}
	out := make([][]uint64, len(pats))
	s := sectionOf(im.text)
	for start := 0; start < s.size; start += scanChunk {
		w, err := s.read(start, start+scanChunk+longest-1)
		if err != nil {
			return nil, err
		}
		for k, p := range pats {
			for i := 0; ; {
				j := bytes.Index(w[i:], p)
				if j < 0 {
					break
				}
				at := i + j
				if at < scanChunk {
					out[k] = append(out[k], im.text.Addr+uint64(start+at))
				}
				i = at + 1
			}
		}
	}
	return out, nil
}

// bunEntry checks that va starts a function: 16-byte aligned, after an int3
// byte, executable, and called directly.
func (im *image) bunEntry(va uint64, called bool) error {
	switch {
	case va%16 != 0:
		return fmt.Errorf("not 16-byte aligned")
	case va == im.text.Addr:
	default:
		b, err := im.readVA(va-1, 1)
		if err != nil || b[0] != 0xcc {
			return fmt.Errorf("not after int3 padding")
		}
	}
	if !im.executable(va) {
		return fmt.Errorf("not in an executable segment")
	}
	if !called {
		return fmt.Errorf("no direct call reaches it")
	}
	return nil
}
