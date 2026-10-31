package tlsoffset

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// synth builds a small stripped x86_64 ELF for the locator tests: every
// section at an address equal to its file offset, no program headers, the
// function table in .eh_frame_hdr and R_X86_64_RELATIVE relocations in
// .rela.dyn, as a static-pie has them. The code is planted byte patterns
// written for these tests, not taken from any binary.
type synth struct {
	text, rodata, relro []byte
	textAddr            uint64
	rodataAddr          uint64
	relroAddr           uint64
	funcs               []uint64
	relocs              [][2]uint64 // offset, addend
}

func newSynth() *synth {
	return &synth{textAddr: 0x1000, rodataAddr: 0x20000, relroAddr: 0x30000}
}

// fn places code at the next 64-byte boundary of .text, records a function
// start there and returns its address.
func (s *synth) fn(code ...byte) uint64 {
	for len(s.text)%64 != 0 {
		s.text = append(s.text, 0xcc)
	}
	at := s.textAddr + uint64(len(s.text))
	s.text = append(s.text, code...)
	s.funcs = append(s.funcs, at)
	return at
}

// str places a NUL-terminated string in .rodata and returns its address.
func (s *synth) str(v string) uint64 {
	at := s.rodataAddr + uint64(len(s.rodata))
	s.rodata = append(s.rodata, v...)
	s.rodata = append(s.rodata, 0)
	return at
}

// raw places bytes in .rodata without a NUL.
func (s *synth) raw(v string) uint64 {
	at := s.rodataAddr + uint64(len(s.rodata))
	s.rodata = append(s.rodata, v...)
	return at
}

// words places 8-byte words in .data.rel.ro (aligned to 8) and returns the
// address of the first.
func (s *synth) words(ws ...uint64) uint64 {
	for len(s.relro)%8 != 0 {
		s.relro = append(s.relro, 0)
	}
	at := s.relroAddr + uint64(len(s.relro))
	for _, w := range ws {
		s.relro = binary.LittleEndian.AppendUint64(s.relro, w)
	}
	return at
}

func (s *synth) reloc(off, addend uint64) { s.relocs = append(s.relocs, [2]uint64{off, addend}) }

// rel32 returns the 4 displacement bytes of an instruction at site, length
// n, whose last four bytes are a displacement to target.
func rel32(site uint64, n int, target uint64) []byte {
	return binary.LittleEndian.AppendUint32(nil, uint32(int32(int64(target)-int64(site)-int64(n))))
}

// at is the address the next byte of .text would get, inside the current
// function.
func (s *synth) at() uint64 { return s.textAddr + uint64(len(s.text)) }

// lea appends "lea rdi, [rip+target]" at the end of .text.
func (s *synth) lea(target uint64) {
	site := s.at()
	s.text = append(s.text, 0x48, 0x8d, 0x3d)
	s.text = append(s.text, rel32(site, 7, target)...)
}

// branch appends a call (0xe8) or jmp (0xe9) to target.
func (s *synth) branch(op byte, target uint64) {
	site := s.at()
	s.text = append(s.text, op)
	s.text = append(s.text, rel32(site, 5, target)...)
}

func (s *synth) bytes(b ...byte) { s.text = append(s.text, b...) }

// write lays the sections out and writes the file.
func (s *synth) write(t *testing.T) string {
	t.Helper()
	var shstr bytes.Buffer
	shstr.WriteByte(0)
	name := func(n string) uint32 {
		off := uint32(shstr.Len())
		shstr.WriteString(n)
		shstr.WriteByte(0)
		return off
	}
	type sec struct {
		name  uint32
		typ   elf.SectionType
		flags elf.SectionFlag
		addr  uint64
		data  []byte
		ent   uint64
	}
	var rela []byte
	sort.Slice(s.relocs, func(i, j int) bool { return s.relocs[i][0] < s.relocs[j][0] })
	for _, r := range s.relocs {
		rela = binary.LittleEndian.AppendUint64(rela, r[0])
		rela = binary.LittleEndian.AppendUint64(rela, rX86_64Relative)
		rela = binary.LittleEndian.AppendUint64(rela, r[1])
	}
	const relaAddr, ehAddr = 0x400, 0x40000
	funcs := append([]uint64(nil), s.funcs...)
	sort.Slice(funcs, func(i, j int) bool { return funcs[i] < funcs[j] })
	eh := []byte{1, 0x1b, 0x03, 0x3b, 0, 0, 0, 0}
	eh = binary.LittleEndian.AppendUint32(eh, uint32(len(funcs)))
	for _, fn := range funcs {
		eh = binary.LittleEndian.AppendUint32(eh, uint32(int32(int64(fn)-ehAddr)))
		eh = binary.LittleEndian.AppendUint32(eh, 0)
	}
	secs := []sec{
		{name: name(".rela.dyn"), typ: elf.SHT_RELA, flags: elf.SHF_ALLOC, addr: relaAddr, data: rela, ent: 24},
		{name: name(".text"), typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, addr: s.textAddr, data: s.text},
		{name: name(".rodata"), typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, addr: s.rodataAddr, data: s.rodata},
		{name: name(".data.rel.ro"), typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, addr: s.relroAddr, data: s.relro},
		{name: name(".eh_frame_hdr"), typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, addr: ehAddr, data: eh},
	}
	shstrName := name(".shstrtab")

	var out bytes.Buffer
	out.Write(make([]byte, 64))
	for _, sc := range secs {
		if uint64(out.Len()) > sc.addr {
			t.Fatalf("section at %#x overlaps the previous one (file at %#x)", sc.addr, out.Len())
		}
		out.Write(make([]byte, int(sc.addr)-out.Len()))
		out.Write(sc.data)
	}
	shstrOff := out.Len()
	out.Write(shstr.Bytes())
	for out.Len()%8 != 0 {
		out.WriteByte(0)
	}
	shoff := out.Len()
	shdr := func(n uint32, typ elf.SectionType, flags elf.SectionFlag, addr, off, size, ent uint64) {
		b := make([]byte, 64)
		binary.LittleEndian.PutUint32(b[0:], n)
		binary.LittleEndian.PutUint32(b[4:], uint32(typ))
		binary.LittleEndian.PutUint64(b[8:], uint64(flags))
		binary.LittleEndian.PutUint64(b[16:], addr)
		binary.LittleEndian.PutUint64(b[24:], off)
		binary.LittleEndian.PutUint64(b[32:], size)
		binary.LittleEndian.PutUint64(b[48:], 1)
		binary.LittleEndian.PutUint64(b[56:], ent)
		out.Write(b)
	}
	shdr(0, elf.SHT_NULL, 0, 0, 0, 0, 0)
	for _, sc := range secs {
		shdr(sc.name, sc.typ, sc.flags, sc.addr, sc.addr, uint64(len(sc.data)), sc.ent)
	}
	shdr(shstrName, elf.SHT_STRTAB, 0, 0, uint64(shstrOff), uint64(shstr.Len()), 0)

	b := out.Bytes()
	copy(b[0:], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(b[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[40:], uint64(shoff))
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[58:], 64)
	binary.LittleEndian.PutUint16(b[60:], uint16(len(secs)+2))
	binary.LittleEndian.PutUint16(b[62:], uint16(len(secs)+1))

	path := filepath.Join(t.TempDir(), "synth.elf")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
