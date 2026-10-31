package tlsoffset

import (
	"errors"
	"reflect"
	"testing"
)

// openSSLSynth plants the call graph ScanOpenSSLEx reads: the two internal
// functions named by their error strings, SSL_write and SSL_read naming
// themselves, SSL_write_ex2 and SSL_read_ex calling the internals,
// SSL_write_ex tail-jumping to SSL_write_ex2, and a BIO-style wrapper
// calling SSL_read_ex. withAnchors false leaves the internal strings out.
type openSSLFuncs struct {
	wInternal, rInternal, sslWrite, sslRead, writeEx2, writeEx, readEx, bioRead uint64
}

func openSSLSynth(withAnchors bool) (*synth, openSSLFuncs) {
	s := newSynth()
	var f openSSLFuncs
	wName, rName := "ssl_write_internal", "ssl_read_internal"
	if !withAnchors {
		wName, rName = "unrelated_write", "unrelated_read"
	}
	wStr, rStr := s.str(wName), s.str(rName)
	// "SSL_write" as the tail of a longer string, as a linker merging
	// string tails leaves it.
	sw := s.str("ossl_SSL_write") + 5
	sr := s.str("SSL_read")
	endbr := []byte{0xf3, 0x0f, 0x1e, 0xfa}

	f.wInternal = s.fn(endbr...)
	s.lea(wStr)
	s.bytes(0xc3)
	f.rInternal = s.fn(endbr...)
	s.lea(rStr)
	s.lea(rStr)
	s.bytes(0xc3)
	f.sslWrite = s.fn(endbr...)
	s.branch(0xe8, f.wInternal)
	s.lea(sw)
	s.bytes(0xc3)
	f.writeEx2 = s.fn(endbr...)
	s.bytes(0x48, 0x83, 0xec, 0x08)
	s.branch(0xe8, f.wInternal)
	s.bytes(0xc3)
	f.writeEx = s.fn(endbr...)
	s.bytes(0x49, 0x89, 0xc8, 0x31, 0xc9) // mov r8, rcx; xor ecx, ecx
	s.branch(0xe9, f.writeEx2)
	f.sslRead = s.fn(endbr...)
	s.branch(0xe8, f.rInternal)
	s.lea(sr)
	s.bytes(0xc3)
	f.readEx = s.fn(endbr...)
	s.branch(0xe8, f.rInternal)
	s.bytes(0xc3)
	f.bioRead = s.fn(endbr...)
	s.bytes(0x55, 0x53, 0x48, 0x83, 0xec, 0x38)
	s.branch(0xe8, f.readEx)
	s.bytes(0xc3)
	s.fn(0x90, 0xc3) // an unrelated function after them
	// SSL_write_ex and SSL_read_ex reached through GOT slots, the wrapper
	// through a method table.
	got := s.words(0, 0, 0)
	s.reloc(got, f.writeEx)
	s.reloc(got+8, f.readEx)
	s.reloc(got+16, f.bioRead)
	return s, f
}

func vas(cs []Candidate) []uint64 {
	var out []uint64
	for _, c := range cs {
		out = append(out, c.VA)
	}
	return out
}

func TestScanOpenSSLEx_Synthetic(t *testing.T) {
	s, f := openSSLSynth(true)
	path := s.write(t)
	for _, chunk := range []int{scanChunk, 64, 37} {
		old := scanChunk
		scanChunk = chunk
		r, err := ScanOpenSSLEx(path)
		scanChunk = old
		if err != nil {
			t.Fatalf("chunk %d: ScanOpenSSLEx: %v", chunk, err)
		}
		if got, want := vas(r.Write), []uint64{f.writeEx, f.writeEx2}; !reflect.DeepEqual(got, want) {
			t.Errorf("chunk %d: write candidates %#x, want %#x (SSL_write_ex first)", chunk, got, want)
		}
		if got, want := vas(r.Read), []uint64{f.readEx, f.bioRead}; !reflect.DeepEqual(got, want) {
			t.Errorf("chunk %d: read candidates %#x, want %#x (SSL_read_ex first)", chunk, got, want)
		}
		for _, c := range append(r.Write, r.Read...) {
			if c.FileOff != c.VA {
				t.Errorf("candidate %#x has file offset %#x; the synthetic file maps them 1:1", c.VA, c.FileOff)
			}
		}
	}
}

func TestScanOpenSSLEx_RefusesWithoutAnchors(t *testing.T) {
	s, _ := openSSLSynth(false)
	_, err := ScanOpenSSLEx(s.write(t))
	if !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("err = %v, want ErrNoAnchor", err)
	}
}

func TestScanOpenSSLEx_RefusesWithoutFunctionTable(t *testing.T) {
	s := newSynth()
	s.str("ssl_write_internal")
	path := s.write(t)
	// A function table with no entries places no reference in a function.
	if _, err := ScanOpenSSLEx(path); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("err = %v, want ErrNoAnchor", err)
	}
}

// rustlsSynth plants what ScanRustlsAEAD reads: a provider source path, a
// panic location naming it, a constructor that loads the location and two
// vtables, an encrypt and a decrypt method, and a vtable with a null
// drop_in_place. version is the rustls version in the path.
type rustlsFuncs struct{ enc, dec, enc2, ctor uint64 }

func rustlsSynth(version string) (*synth, rustlsFuncs) {
	s := newSynth()
	var f rustlsFuncs
	s.raw("unrelated bytes ")
	path := "/home/builder/.cargo/registry/src/index.crates.io-0000/rustls-" + version + "/src/crypto/ring/tls13.rs"
	p := s.raw(path)
	other := s.raw("/rustls-" + version + "/src/crypto/aws_lc_rs/tls12.rs") // no location names it
	_ = other

	drop := s.fn(0xc3)
	// encrypt: mov rax,[rdx+0x10]; mov rbp,[rdx+0x18]; sub rbp,rax; cmp qword [rdx],0
	f.enc = s.fn(0x55, 0x48, 0x8b, 0x42, 0x10, 0x48, 0x8b, 0x6a, 0x18, 0x48, 0x29, 0xc5, 0x48, 0x83, 0x3a, 0x00, 0xc3)
	// decrypt: push rbx; mov rbx,rdi; mov r14,[rdx+0x8]; cmp r14,0x10; ...
	// and the Ok result: mov word [rbx+0x1a],5; mov byte [rbx],0x16
	f.dec = s.fn(0x53, 0x48, 0x89, 0xfb, 0x4c, 0x8b, 0x72, 0x08, 0x49, 0x83, 0xfe, 0x10,
		0x4c, 0x89, 0x73, 0x08, 0x66, 0xc7, 0x43, 0x1a, 0x05, 0x00, 0xc6, 0x03, 0x16, 0x5b, 0xc3)
	f.enc2 = s.fn(0x48, 0x83, 0x3a, 0x00, 0xc3)

	loc := s.words(0, uint64(len(path)), 77|9<<32)
	s.reloc(loc, p)
	vtEnc := s.words(0, 0x230, 8, 0, 0)
	s.reloc(vtEnc, drop)
	s.reloc(vtEnc+24, f.enc)
	s.reloc(vtEnc+32, drop)
	vtDec := s.words(0, 0x28, 8, 0)
	s.reloc(vtDec, drop)
	s.reloc(vtDec+24, f.dec)
	vtNull := s.words(0, 0x230, 16, 0) // no drop glue: a null first slot
	s.reloc(vtNull+24, f.enc2)
	notVt := s.words(0, 0, 0, 0) // size 0: not a vtable
	s.reloc(notVt, drop)
	s.reloc(notVt+24, f.dec)

	f.ctor = s.fn()
	s.lea(vtEnc)
	s.lea(loc)
	s.lea(vtDec)
	s.lea(vtNull)
	s.lea(notVt)
	s.bytes(0xc3)
	s.fn(0x90, 0xc3)
	return s, f
}

func TestScanRustlsAEAD_Synthetic(t *testing.T) {
	s, f := rustlsSynth("0.23.46")
	path := s.write(t)
	for _, chunk := range []int{scanChunk, 64, 29} {
		old := scanChunk
		scanChunk = chunk
		r, err := ScanRustlsAEAD(path)
		scanChunk = old
		if err != nil {
			t.Fatalf("chunk %d: ScanRustlsAEAD: %v", chunk, err)
		}
		if r.Version != "0.23.46" || r.OkTag != 0x16 {
			t.Errorf("chunk %d: version %q ok tag %d, want 0.23.46 and 22", chunk, r.Version, r.OkTag)
		}
		got := map[uint64]bool{}
		for _, m := range r.Methods {
			got[m.VA] = m.Encrypt
			if m.Provider != "ring" || m.Protocol != "tls13" {
				t.Errorf("method %#x: %s/%s, want ring/tls13", m.VA, m.Provider, m.Protocol)
			}
		}
		want := map[uint64]bool{f.enc: true, f.dec: false, f.enc2: true}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("chunk %d: methods %v, want %v", chunk, got, want)
		}
	}
}

func TestScanRustlsAEAD_Refuses(t *testing.T) {
	s, _ := rustlsSynth("0.24.1")
	if _, err := ScanRustlsAEAD(s.write(t)); !errors.Is(err, ErrNoAnchor) {
		t.Errorf("rustls 0.24.1: err = %v, want ErrNoAnchor (layout not measured)", err)
	}
	s2, _ := openSSLSynth(true)
	if _, err := ScanRustlsAEAD(s2.write(t)); !errors.Is(err, ErrNoAnchor) {
		t.Errorf("no rustls: err = %v, want ErrNoAnchor", err)
	}
}

func TestClassifyAEAD(t *testing.T) {
	for _, tc := range []struct {
		name    string
		head    []byte
		encrypt bool
		ok      bool
	}{
		{"encrypt tests the chunks discriminant", []byte{0x48, 0x8b, 0x42, 0x10, 0x48, 0x83, 0x3a, 0x00}, true, true},
		{"tls13 decrypt, r14 against 16", []byte{0x53, 0x4c, 0x8b, 0x72, 0x08, 0x49, 0x83, 0xfe, 0x10}, false, true},
		{"tls12 decrypt, rax against 24 after other code", []byte{0x48, 0x8b, 0x42, 0x08, 0x90, 0x90, 0x48, 0x83, 0xf8, 0x18}, false, true},
		{"length compared in another register", []byte{0x4c, 0x8b, 0x72, 0x08, 0x49, 0x83, 0xff, 0x10}, false, false},
		{"compared with 32", []byte{0x4c, 0x8b, 0x72, 0x08, 0x49, 0x83, 0xfe, 0x20}, false, false},
		{"nothing", []byte{0x90, 0xc3}, false, false},
	} {
		enc, ok := classifyAEAD(tc.head)
		if enc != tc.encrypt || ok != tc.ok {
			t.Errorf("%s: (%v, %v), want (%v, %v)", tc.name, enc, ok, tc.encrypt, tc.ok)
		}
	}
}

func TestLiteralOkStores(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		want []int
	}{
		{"rbx", []byte{0x66, 0xc7, 0x43, 0x1a, 0x05, 0x00, 0xc6, 0x03, 0x16}, []int{0x16}},
		{"r14 with REX", []byte{0x66, 0x41, 0xc7, 0x46, 0x1a, 0x05, 0x00, 0x41, 0xc6, 0x06, 0x16}, []int{0x16}},
		{"another base register for the byte", []byte{0x66, 0xc7, 0x43, 0x1a, 0x05, 0x00, 0xc6, 0x06, 0x16}, nil},
		{"register store, not a literal", []byte{0x66, 0x89, 0x43, 0x1a, 0x40, 0x88, 0x2b}, nil},
	} {
		if got := literalOkStores(tc.code); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
