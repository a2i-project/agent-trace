package tlsoffset

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// The Go crypto/tls locator for the content method tls-go-crypto (N-47). A
// Go executable keeps its function table, the pclntab, even when stripped:
// the runtime needs it for stack traces and the garbage collector. From it
// the locator reads the entry and the bounds of crypto/tls.(*Conn).Write and
// (*Conn).Read, and, from each function's stack-pointer table (pcsp), its
// return instructions: Go's moving stacks make a uretprobe unsafe, so the
// probes sit at each RET.

// GoFunc is one located Go function: its entry, its end and the RET
// instructions inside it, each with its file offset.
type GoFunc struct {
	Name    string
	Entry   Candidate
	End     uint64
	Returns []Candidate
}

// GoTLSResult is what ScanGoTLS found.
type GoTLSResult struct {
	BuildID   string
	GoVersion string // from the build information; "" when unreadable
	Write     GoFunc // crypto/tls.(*Conn).Write
	Read      GoFunc // crypto/tls.(*Conn).Read
}

// Names of the hooked functions, as the pclntab spells them.
const (
	GoTLSWrite = "crypto/tls.(*Conn).Write"
	GoTLSRead  = "crypto/tls.(*Conn).Read"
)

// pclntab header (Go 1.20 and later, runtime.pcHeader): the magic, two zero
// bytes, the instruction size quantum (1 on amd64) and the pointer size.
var goPclntabHead = []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x08}

// Field offsets of runtime.moduledata (Go 1.20 and later) the locator reads.
const (
	mdPcHeader    = 0
	mdFuncnametab = 8
	mdFtab        = 128
	mdMinpc       = 160
	mdText        = 176
)

// gopcln is a parsed pclntab: its address and the offsets of its tables.
type gopcln struct {
	sec       section // the section that holds it, read in windows
	secAddr   uint64
	off       int // the header's offset in sec
	va        uint64
	nfunc     int
	funcname  int // offsets from the header
	pctab     int
	ftab      int
	textStart uint64
}

// ScanGoTLS locates crypto/tls.(*Conn).Write and (*Conn).Read in a Go
// executable for amd64 built by Go 1.20 or later, with or without symbols,
// linked internally or externally. It refuses with ErrNoAnchor when the
// pclntab, the module data that names the text start, either function, or
// any RET in it is not found, or when a function has no stack frame (its
// returns would not be told apart by the table).
func ScanGoTLS(path string) (GoTLSResult, error) {
	f, err := elf.Open(path)
	if err != nil {
		return GoTLSResult{}, fmt.Errorf("open elf: %w", err)
	}
	defer func() { _ = f.Close() }()
	if f.Machine != elf.EM_X86_64 || f.Class != elf.ELFCLASS64 {
		return GoTLSResult{}, fmt.Errorf("%w: not an x86_64 executable", ErrNoAnchor)
	}
	res := GoTLSResult{BuildID: getBuildID(f)}
	if bi, err := buildinfo.ReadFile(path); err == nil {
		res.GoVersion = bi.GoVersion
	}
	p, err := findPclntab(f)
	if err != nil {
		return res, err
	}
	if p.textStart, err = goTextStart(f, p); err != nil {
		return res, err
	}
	funcs, err := p.lookup(GoTLSWrite, GoTLSRead)
	if err != nil {
		return res, err
	}
	for i := range funcs {
		if funcs[i], err = placeGoFunc(f, funcs[i]); err != nil {
			return res, err
		}
	}
	res.Write, res.Read = funcs[0], funcs[1]
	return res, nil
}

// placeGoFunc checks that fn lies in an executable segment, keeps the RET
// each candidate run holds (retInRun), and sets every file offset.
func placeGoFunc(f *elf.File, fn GoFunc) (GoFunc, error) {
	if !executableVA(f, fn.Entry.VA) || !executableVA(f, fn.End-1) {
		return fn, fmt.Errorf("%w: %s at %#x is not in an executable segment", ErrNoAnchor, fn.Name, fn.Entry.VA)
	}
	im := &image{f: f}
	fn.Entry.FileOff = vaToFileOff(f, fn.Entry.VA)
	var rets []Candidate
	for _, c := range fn.Returns {
		n := min(retWalk, int(fn.End-c.VA))
		b, err := im.readVA(c.VA, n)
		if err != nil {
			return fn, err
		}
		if at, ok := retInRun(b); ok {
			va := c.VA + uint64(at)
			rets = append(rets, Candidate{VA: va, FileOff: vaToFileOff(f, va)})
		}
	}
	if len(rets) == 0 {
		return fn, fmt.Errorf("%w: %s has no return", ErrNoAnchor, fn.Name)
	}
	fn.Returns = rets
	return fn, nil
}

// findPclntab returns the pclntab: the .gopclntab section when there is one,
// else the first header found at a 16-byte boundary of a read-only allocated
// section (a linker that merges .gopclntab into another section, as agy's
// does into .lrodata), whose tables lie inside the section.
func findPclntab(f *elf.File) (*gopcln, error) {
	try := func(s *elf.Section, off int) *gopcln {
		sec := sectionOf(s)
		h, err := sec.read(off, off+72)
		if err != nil || len(h) < 72 || !bytes.Equal(h[:8], goPclntabHead) {
			return nil
		}
		u := func(i int) uint64 { return binary.LittleEndian.Uint64(h[i:]) }
		p := &gopcln{sec: sec, secAddr: s.Addr, off: off, va: s.Addr + uint64(off), nfunc: int(u(8)),
			funcname: int(u(32)), pctab: int(u(56)), ftab: int(u(64))}
		size := uint64(sec.size - off)
		if p.nfunc <= 0 || p.nfunc > 1<<24 || u(32) < 72 || u(32) > u(40) || u(40) > u(48) || u(48) > u(56) || u(56) > u(64) ||
			u(64)+8*uint64(p.nfunc+1) > size {
			return nil
		}
		return p
	}
	if s := f.Section(".gopclntab"); s != nil {
		if p := try(s, 0); p != nil {
			return p, nil
		}
	}
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_ALLOC == 0 || s.Flags&elf.SHF_EXECINSTR != 0 || s.Type != elf.SHT_PROGBITS {
			continue
		}
		sec := sectionOf(s)
		for start := 0; start < sec.size; start += scanChunk {
			w, err := sec.read(start, start+scanChunk+len(goPclntabHead))
			if err != nil {
				return nil, err
			}
			for i := 0; ; {
				j := bytes.Index(w[i:], goPclntabHead)
				if j < 0 {
					break
				}
				at := i + j
				if (start+at)%16 == 0 && at < scanChunk {
					if p := try(s, start+at); p != nil {
						return p, nil
					}
				}
				i = at + 1
			}
		}
	}
	return nil, fmt.Errorf("%w: no Go 1.20+ pclntab", ErrNoAnchor)
}

// goTextStart returns the address the pclntab's entry offsets count from:
// runtime.moduledata.text of the module whose pcHeader is p. The module data
// is found by its pointer to the pclntab, stored as a relocation in a
// position-independent executable and as a plain word otherwise, and is
// accepted only when its funcnametab and ftab point into the same pclntab
// and its minpc equals its text.
func goTextStart(f *elf.File, p *gopcln) (uint64, error) {
	rela := f.Section(".rela.dyn")
	if rela == nil {
		rela = f.Section(".rela")
	}
	im := &image{f: f, rela: rela}
	// Candidates: relocations whose addend is the pclntab's address, and
	// words holding it in the writable data sections.
	var cands []uint64
	if err := im.forEachRelative(func(off, addend uint64) {
		if addend == p.va {
			cands = append(cands, off)
		}
	}); err != nil {
		return 0, err
	}
	want := binary.LittleEndian.AppendUint64(nil, p.va)
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_ALLOC == 0 || s.Flags&elf.SHF_WRITE == 0 || s.Type != elf.SHT_PROGBITS {
			continue
		}
		sec := sectionOf(s)
		for start := 0; start < sec.size; start += scanChunk {
			w, err := sec.read(start, start+scanChunk)
			if err != nil {
				return 0, err
			}
			for i := 0; i+8 <= len(w); i += 8 {
				if (start+i)%8 == 0 && bytes.Equal(w[i:i+8], want) {
					cands = append(cands, s.Addr+uint64(start+i))
				}
			}
		}
	}
	for _, md := range cands {
		words, err := relocatedWords(f, im, md, []uint64{mdPcHeader, mdFuncnametab, mdFtab, mdMinpc, mdText})
		if err != nil {
			continue
		}
		if words[0] == p.va && words[1] == p.va+uint64(p.funcname) && words[2] == p.va+uint64(p.ftab) && words[3] == words[4] && words[4] != 0 {
			return words[4], nil
		}
	}
	return 0, fmt.Errorf("%w: no module data names the pclntab at %#x", ErrNoAnchor, p.va)
}

// relocatedWords reads the 8-byte words at base+offs as the loader leaves
// them: a relative relocation's addend where one applies, else the file's
// bytes.
func relocatedWords(f *elf.File, im *image, base uint64, offs []uint64) ([]uint64, error) {
	out := make([]uint64, len(offs))
	want := map[uint64]int{}
	for i, o := range offs {
		b, err := (&image{f: f}).readVA(base+o, 8)
		if err != nil {
			return nil, err
		}
		out[i] = binary.LittleEndian.Uint64(b)
		want[base+o] = i
	}
	err := im.forEachRelative(func(off, addend uint64) {
		if i, ok := want[off]; ok {
			out[i] = addend
		}
	})
	return out, err
}

// executableVA reports whether va lies in the file-backed part of an
// executable PT_LOAD segment.
func executableVA(f *elf.File, va uint64) bool {
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && va >= p.Vaddr && va < p.Vaddr+p.Filesz {
			return true
		}
	}
	return false
}

// winReader reads a section through one cached window, for the pclntab's
// mostly sequential small reads.
type winReader struct {
	sec   section
	start int
	buf   []byte
}

func (r *winReader) bytes(off, n int) ([]byte, error) {
	if off < r.start || off+n > r.start+len(r.buf) {
		b, err := r.sec.read(off, off+max(scanChunk, n))
		if err != nil {
			return nil, err
		}
		r.start, r.buf = off, b
	}
	if off+n > r.start+len(r.buf) {
		return nil, fmt.Errorf("read %d bytes at %d: past the end of the pclntab section", n, off)
	}
	return r.buf[off-r.start : off-r.start+n], nil
}

func (r *winReader) u32(off int) (uint32, error) {
	b, err := r.bytes(off, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// lookup finds each named function, in the order of names, with its RET
// sites. Each name must name exactly one function.
func (p *gopcln) lookup(names ...string) ([]GoFunc, error) {
	// Three windows, one per table, each read mostly in order.
	r := &winReader{sec: p.sec}
	rf := &winReader{sec: p.sec}
	rn := &winReader{sec: p.sec}
	ftab := p.off + p.ftab
	want := map[string]int{}
	longest := 0
	for i, n := range names {
		want[n] = i
		longest = max(longest, len(n))
	}
	// nameAt reads the name at nameOff only as far as the longest wanted
	// name and its NUL; a longer name reads as "".
	nameAt := func(nameOff int32) (string, error) {
		at := p.off + p.funcname + int(nameOff)
		n := min(longest+1, p.sec.size-at)
		if n <= 0 {
			return "", fmt.Errorf("%w: function name past the pclntab", ErrNoAnchor)
		}
		b, err := rn.bytes(at, n)
		if err != nil {
			return "", err
		}
		if i := bytes.IndexByte(b, 0); i >= 0 {
			return string(b[:i]), nil
		}
		return "", nil
	}
	out := make([]GoFunc, len(names))
	found := make([]bool, len(names))
	for i := 0; i < p.nfunc; i++ {
		entry, err := r.u32(ftab + 8*i)
		if err != nil {
			return nil, err
		}
		funcoff, err := r.u32(ftab + 8*i + 4)
		if err != nil {
			return nil, err
		}
		fo := ftab + int(funcoff)
		nameOff, err := rf.u32(fo + 4)
		if err != nil {
			return nil, err
		}
		name, err := nameAt(int32(nameOff))
		if err != nil {
			return nil, err
		}
		k, ok := want[name]
		if !ok {
			continue
		}
		if found[k] {
			return nil, fmt.Errorf("%w: %s named twice in the pclntab", ErrNoAnchor, name)
		}
		next, err := r.u32(ftab + 8*(i+1))
		if err != nil {
			return nil, err
		}
		pcsp, err := rf.u32(fo + 16)
		if err != nil {
			return nil, err
		}
		fn := GoFunc{Name: name, Entry: Candidate{VA: p.textStart + uint64(entry)}, End: p.textStart + uint64(next)}
		if fn.End <= fn.Entry.VA {
			return nil, fmt.Errorf("%w: %s has no extent", ErrNoAnchor, name)
		}
		if fn.Returns, err = p.returns(fn, int(pcsp)); err != nil {
			return nil, err
		}
		out[k], found[k] = fn, true
	}
	for k, ok := range found {
		if !ok {
			return nil, fmt.Errorf("%w: %s not in the pclntab", ErrNoAnchor, names[k])
		}
	}
	return out, nil
}

// retWalk bounds the bytes retInRun reads from a run's start.
const retWalk = 32

// retInRun returns the offset of the RET that ends an epilogue run b: the
// run starts at an instruction boundary, and the RET is either its first
// instruction or follows only no-op instructions (Go puts a NOP between
// LEAVE and RET on some paths), whose encodings and lengths are known.
// Anything else (the stack-growth call at the end of a function) holds no
// RET this way.
func retInRun(b []byte) (int, bool) {
	at := 0
	for at < len(b) {
		if b[at] == 0xc3 {
			return at, true
		}
		n := nopLen(b[at:])
		if n == 0 {
			return 0, false
		}
		at += n
	}
	return 0, false
}

// nopLen returns the length of the no-op instruction b begins with, or 0:
// NOP (90), XCHG AX,AX (66 90) and the multi-byte NOP 0F 1F /0 in the forms
// assemblers emit, with an optional 66 prefix.
func nopLen(b []byte) int {
	switch {
	case len(b) >= 1 && b[0] == 0x90:
		return 1
	case len(b) >= 2 && b[0] == 0x66 && b[1] == 0x90:
		return 2
	}
	pre := 0
	if len(b) > 0 && b[0] == 0x66 {
		pre = 1
	}
	if len(b) < pre+3 || b[pre] != 0x0f || b[pre+1] != 0x1f {
		return 0
	}
	var n int
	switch b[pre+2] {
	case 0x00:
		n = 3
	case 0x40:
		n = 4
	case 0x44:
		n = 5
	case 0x80:
		n = 7
	case 0x84:
		n = 8
	default:
		return 0
	}
	if len(b) < pre+n {
		return 0
	}
	return pre + n
}

// pcValue is one run of a pc-value table: the value holds on [start, end).
type pcValue struct {
	start, end uint64
	value      int32
}

// pcValues decodes the pc-value table at offset off of pctab for a function
// starting at entry (runtime.step: a zig-zag value delta and a pc delta per
// run, both varints, ended by a zero value delta after the first run).
func (p *gopcln) pcValues(entry uint64, off int) ([]pcValue, error) {
	at := p.off + p.pctab + off
	b, err := p.sec.read(at, at+64<<10)
	if err != nil {
		return nil, err
	}
	var out []pcValue
	pc, val := entry, int32(-1)
	for first := true; ; first = false {
		uv, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, fmt.Errorf("%w: pc-value table cut short", ErrNoAnchor)
		}
		if uv == 0 && !first {
			return out, nil
		}
		b = b[n:]
		val += int32(-(uv & 1) ^ (uv >> 1))
		pd, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, fmt.Errorf("%w: pc-value table cut short", ErrNoAnchor)
		}
		b = b[n:]
		out = append(out, pcValue{start: pc, end: pc + pd, value: val})
		pc += pd
		if len(out) > 1<<16 {
			return nil, fmt.Errorf("%w: pc-value table too long", ErrNoAnchor)
		}
	}
}

// returns finds the runs that may hold fn's RET instructions, from its
// stack-pointer table; placeGoFunc keeps the RET each holds. A Go function
// with a frame changes the stack pointer at each instruction of its
// epilogue, so the RET that follows is in a run whose value is 0 (the frame
// popped), first or after no-op instructions only (retInRun); the other runs
// at 0 are the prologue, at the entry, and the stack-growth call at the end,
// which holds no RET this way. The start of a run is an instruction
// boundary. A function whose stack pointer never moves is refused: its runs
// do not mark its returns.
func (p *gopcln) returns(fn GoFunc, pcsp int) ([]Candidate, error) {
	runs, err := p.pcValues(fn.Entry.VA, pcsp)
	if err != nil {
		return nil, err
	}
	framed := false
	for _, r := range runs {
		if r.value != 0 {
			framed = true
		}
		if r.end > fn.End {
			return nil, fmt.Errorf("%w: %s pc-value runs past its end", ErrNoAnchor, fn.Name)
		}
	}
	if !framed {
		return nil, fmt.Errorf("%w: %s has no stack frame", ErrNoAnchor, fn.Name)
	}
	var out []Candidate
	for i, r := range runs {
		if i == 0 || r.value != 0 || r.end == r.start {
			continue
		}
		out = append(out, Candidate{VA: r.start})
	}
	return out, nil
}
