package tlsoffset

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// AEADMethod is one rustls MessageEncrypter::encrypt or
// MessageDecrypter::decrypt implementation, the first method of its trait
// object's vtable.
type AEADMethod struct {
	VA, FileOff uint64
	Encrypt     bool   // encrypt, else decrypt
	Provider    string // "aws_lc_rs" or "ring", from the panic location's path
	Protocol    string // "tls13" or "tls12"
	Vtable      uint64
}

// AEADResult is what ScanRustlsAEAD found.
type AEADResult struct {
	BuildID string
	// Version is the rustls version the source paths name, such as
	// "0.23.46".
	Version string
	Methods []AEADMethod
	// OkTag is the first byte decrypt writes to its result for Ok, the
	// discriminant of Result<InboundPlainMessage, Error>, read from the
	// TLS 1.3 decrypt methods' literal store; -1 when they do not agree or
	// none stores a literal.
	OkTag int
}

// SupportedRustls is the rustls minor series whose record layouts the
// tls-rustls-aead probes read (N-38); ScanRustlsAEAD refuses another.
const SupportedRustls = "0.23."

// rustlsPath matches the source path of rustls's per-provider record
// encryption files, which a stripped binary keeps for its panic locations.
var rustlsPath = regexp.MustCompile(`/rustls-(\d+\.\d+\.\d+)/src/crypto/(aws_lc_rs|ring)/(tls13|tls12)\.rs`)

// maxLocationPath bounds the length of a panic location's file name.
const maxLocationPath = 512

// ScanRustlsAEAD finds the rustls AEAD record methods of a stripped
// executable for the content method tls-rustls-aead (N-38), with no symbol:
//
//  1. The source paths .../rustls-<v>/src/crypto/{aws_lc_rs,ring}/{tls13,tls12}.rs
//     in .rodata, and the core::panic::Location records {file ptr, file
//     len, line, column} whose file is one of them (the pointer is a
//     relative relocation; its address plus the length must end the path).
//  2. The functions that load such a record (RIP-relative lea): the
//     encrypter and decrypter constructors, which unwrap.
//  3. In those functions, the leas into a writable relocated section of a
//     trait vtable: drop_in_place (a function, or null for a type without
//     drop glue), size, alignment, then the methods; the first method is
//     encrypt or decrypt.
//  4. Each first method is classified by its first instructions: encrypt
//     tests the OutboundChunks discriminant (cmp qword [rdx], 0); decrypt
//     loads the payload length ([rdx+8]) and compares it with the tag size
//     (16) or the explicit nonce plus tag (24).
//
// ErrNoAnchor when no path, no location, or no classified method of each
// kind is found, or the version is not in SupportedRustls.
func ScanRustlsAEAD(path string) (AEADResult, error) {
	f, err := elf.Open(path)
	if err != nil {
		return AEADResult{}, fmt.Errorf("open elf: %w", err)
	}
	defer func() { _ = f.Close() }()
	res := AEADResult{BuildID: getBuildID(f), OkTag: -1}
	im, err := newImage(f)
	if err != nil {
		return res, err
	}
	if err := im.rustlsAEAD(&res); err != nil {
		return res, err
	}
	return res, nil
}

type rustlsFile struct{ version, provider, protocol string }

func (im *image) rustlsAEAD(res *AEADResult) error {
	paths, err := im.regexpsAt(rustlsPath, 96)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("%w: no rustls crypto provider source path", ErrNoAnchor)
	}

	// 1. Location records: a relocation whose addend starts a path that
	// ends at a match, the length stored after it saying so.
	type pending struct {
		off, addend uint64
		end         uint64 // the end of the path the record must name
		file        rustlsFile
	}
	var near []pending
	if err := im.forEachRelative(func(off, addend uint64) {
		i := sort.Search(len(paths), func(i int) bool { return paths[i].end > addend })
		for ; i < len(paths) && paths[i].end-addend <= maxLocationPath; i++ {
			if addend <= paths[i].start {
				p := paths[i]
				near = append(near, pending{off: off, addend: addend, end: p.end, file: rustlsFile{p.groups[0], p.groups[1], p.groups[2]}})
			}
		}
	}); err != nil {
		return err
	}
	locs := map[uint64]rustlsFile{}
	for _, p := range near {
		b, err := im.readVA(p.off+8, 16)
		if err != nil {
			continue
		}
		n := binary.LittleEndian.Uint64(b[:8])
		line := binary.LittleEndian.Uint32(b[8:12])
		if line == 0 || line > 100000 || p.addend+n != p.end {
			continue
		}
		locs[p.off] = p.file
	}
	if len(locs) == 0 {
		return fmt.Errorf("%w: no panic location names a rustls crypto provider file", ErrNoAnchor)
	}

	// 2. The functions that load a location record.
	targets := map[uint64]bool{}
	for off := range locs {
		targets[off] = true
	}
	refs, err := im.leaRefs(targets)
	if err != nil {
		return err
	}
	ctors := map[uint64]rustlsFile{}
	for _, r := range refs {
		if start, _, ok := im.function(r.site); ok {
			ctors[start] = locs[r.target]
		}
	}

	// 3. Vtables loaded by those functions.
	type vt struct {
		addr uint64
		file rustlsFile
	}
	var vts []vt
	for start, file := range ctors {
		_, end, ok := im.function(start)
		if !ok || end <= start || end-start > 1<<16 {
			continue
		}
		code, err := im.readVA(start, int(end-start))
		if err != nil {
			continue
		}
		for i := 0; i+7 <= len(code); i++ {
			if (code[i] != 0x48 && code[i] != 0x4c) || code[i+1] != 0x8d || code[i+2]&0xc7 != 0x05 {
				continue
			}
			t := uint64(int64(start) + int64(i) + 7 + int64(int32(binary.LittleEndian.Uint32(code[i+3:i+7]))))
			if s := im.sectionAt(t); s != nil && s.Flags&elf.SHF_WRITE != 0 && s.Type == elf.SHT_PROGBITS {
				vts = append(vts, vt{t, file})
			}
		}
	}
	slots := map[uint64]uint64{}
	want := map[uint64]bool{}
	for _, v := range vts {
		want[v.addr] = true
		want[v.addr+24] = true
	}
	if err := im.forEachRelative(func(off, addend uint64) {
		if want[off] {
			slots[off] = addend
		}
	}); err != nil {
		return err
	}

	seen := map[uint64]bool{}
	versions := map[string]bool{}
	for _, v := range vts {
		raw, err := im.readVA(v.addr, 24)
		if err != nil {
			continue
		}
		drop, dropRel := slots[v.addr]
		size := binary.LittleEndian.Uint64(raw[8:16])
		align := binary.LittleEndian.Uint64(raw[16:24])
		m0, ok := slots[v.addr+24]
		switch {
		case !ok || !im.inText(m0):
			continue
		case dropRel && !im.inText(drop):
			continue
		case !dropRel && binary.LittleEndian.Uint64(raw[:8]) != 0:
			continue
		case size == 0 || size >= 0x1000:
			continue
		case align != 1 && align != 2 && align != 4 && align != 8 && align != 16:
			continue
		}
		if seen[m0] {
			continue
		}
		// The first 0x50 bytes, never past the method's own end.
		n := 0x50
		if start, end, ok := im.function(m0); ok && start == m0 && end-start < uint64(n) {
			n = int(end - start)
		}
		head, err := im.readVA(m0, n)
		if err != nil {
			continue
		}
		kind, ok := classifyAEAD(head)
		if !ok {
			continue
		}
		seen[m0] = true
		versions[v.file.version] = true
		res.Methods = append(res.Methods, AEADMethod{VA: m0, FileOff: vaToFileOff(im.f, m0), Encrypt: kind, Provider: v.file.provider, Protocol: v.file.protocol, Vtable: v.addr})
	}
	sort.Slice(res.Methods, func(i, j int) bool { return res.Methods[i].VA < res.Methods[j].VA })

	var enc, dec int
	for _, m := range res.Methods {
		if m.Encrypt {
			enc++
		} else {
			dec++
		}
	}
	if enc == 0 || dec == 0 {
		return fmt.Errorf("%w: %d rustls encrypt and %d decrypt methods classified, need both", ErrNoAnchor, enc, dec)
	}
	if len(versions) != 1 {
		return fmt.Errorf("%w: rustls source paths of %d versions", ErrNoAnchor, len(versions))
	}
	for v := range versions {
		res.Version = v
	}
	if !strings.HasPrefix(res.Version, SupportedRustls) {
		return fmt.Errorf("%w: rustls %s, the probes read the record layout of %sx", ErrNoAnchor, res.Version, SupportedRustls)
	}
	res.OkTag = im.okTag(res.Methods)
	return nil
}

// classifyAEAD tells encrypt from decrypt by the first bytes of a method:
// encrypt tests the OutboundChunks discriminant (cmp qword [rdx], 0);
// decrypt loads the payload length from [rdx+8] into a register and, within
// 12 bytes, compares that register with 16 or 24 (cmp r64, imm8). Byte
// matching, not regexp, which reads its input as UTF-8.
func classifyAEAD(head []byte) (encrypt, ok bool) {
	if bytes.Contains(head, []byte{0x48, 0x83, 0x3a, 0x00}) {
		return true, true
	}
	for i := 0; i+4 <= len(head); i++ {
		rex := head[i]
		if (rex != 0x48 && rex != 0x4c) || head[i+1] != 0x8b || head[i+2]&0xc7 != 0x42 || head[i+3] != 0x08 {
			continue
		}
		reg := (head[i+2] >> 3) & 7
		cmpRex := byte(0x48)
		if rex == 0x4c {
			cmpRex = 0x49
		}
		for j := i + 4; j <= i+4+12 && j+4 <= len(head); j++ {
			if head[j] == cmpRex && head[j+1] == 0x83 && head[j+2] == 0xf8|reg && (head[j+3] == 0x10 || head[j+3] == 0x18) {
				return false, true
			}
		}
	}
	return false, false
}

// okTag reads the Ok discriminant from the TLS 1.3 decrypt methods: the
// literal byte stored at [r] right after the literal ProtocolVersion word
// at [r+0x1a] (mov word [r+0x1a], imm16; mov byte [r], imm8). -1 unless
// every method that has the pair agrees and at least one has it.
func (im *image) okTag(ms []AEADMethod) int {
	tag := -1
	for _, m := range ms {
		if m.Encrypt || m.Protocol != "tls13" {
			continue
		}
		_, end, ok := im.function(m.VA)
		if !ok || end <= m.VA || end-m.VA > 1<<14 {
			continue
		}
		code, err := im.readVA(m.VA, int(end-m.VA))
		if err != nil {
			continue
		}
		for _, t := range literalOkStores(code) {
			if tag >= 0 && tag != t {
				return -1
			}
			tag = t
		}
	}
	return tag
}

// literalOkStores returns the imm8 of each "mov word [r+0x1a], imm16" that
// is followed by "mov byte [r], imm8" on the same base register (r not rsp,
// rbp or their r12/r13 forms, which need other encodings).
func literalOkStores(code []byte) []int {
	var out []int
	for i := 0; i+9 <= len(code); i++ {
		if code[i] != 0x66 {
			continue
		}
		j := i + 1
		rex := byte(0)
		if code[j] == 0x41 {
			rex, j = 0x41, j+1
		}
		if j+5 > len(code) || code[j] != 0xc7 || code[j+1]&0xf8 != 0x40 || code[j+2] != 0x1a {
			continue
		}
		reg := code[j+1] & 7
		if reg == 4 || reg == 5 {
			continue
		}
		k := j + 5
		if rex != 0 {
			if k+4 > len(code) || code[k] != 0x41 {
				continue
			}
			k++
		}
		if k+3 > len(code) || code[k] != 0xc6 || code[k+1] != reg {
			continue
		}
		out = append(out, int(code[k+2]))
	}
	return out
}
