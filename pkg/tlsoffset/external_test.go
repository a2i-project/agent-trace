package tlsoffset

import (
	"debug/elf"
	"errors"
	"os"
	"testing"
)

// TestLocators_ExternalBinary runs the anchor locators on the executable
// AGENT_TRACE_LOCATOR_BIN names, for checking them on a real build that the
// repository cannot hold. Skipped without it.
func TestLocators_ExternalBinary(t *testing.T) {
	path := os.Getenv("AGENT_TRACE_LOCATOR_BIN")
	if path == "" {
		t.Skip("AGENT_TRACE_LOCATOR_BIN not set")
	}
	ex, err := ScanOpenSSLEx(path)
	switch {
	case errors.Is(err, ErrNoAnchor):
		t.Logf("tls-openssl-ex: %v", err)
	case err != nil:
		t.Fatalf("ScanOpenSSLEx: %v", err)
	default:
		for _, c := range ex.Write {
			t.Logf("SSL_write_ex candidate %#x score %d", c.VA, c.Score)
		}
		for _, c := range ex.Read {
			t.Logf("SSL_read_ex candidate %#x score %d", c.VA, c.Score)
		}
	}
	r, err := ScanRustlsAEAD(path)
	switch {
	case errors.Is(err, ErrNoAnchor):
		t.Logf("tls-rustls-aead: %v", err)
	case err != nil:
		t.Fatalf("ScanRustlsAEAD: %v", err)
	default:
		t.Logf("rustls %s, ok tag %d", r.Version, r.OkTag)
		for _, m := range r.Methods {
			t.Logf("%s/%s encrypt=%v method %#x vtable %#x", m.Provider, m.Protocol, m.Encrypt, m.VA, m.Vtable)
		}
	}
	g, err := ScanGoTLS(path)
	switch {
	case errors.Is(err, ErrNoAnchor):
		t.Logf("tls-go-crypto: %v", err)
	case err != nil:
		t.Fatalf("ScanGoTLS: %v", err)
	default:
		t.Logf("Go %s", g.GoVersion)
		for _, fn := range []GoFunc{g.Write, g.Read} {
			t.Logf("%s entry %#x end %#x returns %x", fn.Name, fn.Entry.VA, fn.End, vas(fn.Returns))
		}
	}
}

// TestLocators_AttachPointsAreFunctionEntries checks, on the executable
// AGENT_TRACE_LOCATOR_BIN names (skipped without it), that every attach
// point the locators return is a function entry of the unwind table inside
// an executable segment, and that its file offset maps back to it: a probe
// at a byte that is not an instruction boundary corrupts the process.
func TestLocators_AttachPointsAreFunctionEntries(t *testing.T) {
	path := os.Getenv("AGENT_TRACE_LOCATOR_BIN")
	if path == "" {
		t.Skip("AGENT_TRACE_LOCATOR_BIN not set")
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	im, err := newImage(f)
	if err != nil {
		t.Skipf("no function table: %v", err)
	}
	check := func(kind string, va, off uint64) {
		start, _, ok := im.function(va)
		if !ok || start != va || !im.executable(va) || vaToFileOff(f, va) != off {
			t.Errorf("%s at %#x (file offset %#x) is not a function entry in an executable segment", kind, va, off)
		}
	}
	if ex, err := ScanOpenSSLEx(path); err == nil {
		for _, c := range append(ex.Write, ex.Read...) {
			if c.VA != 0 {
				check("OpenSSL candidate", c.VA, c.FileOff)
			}
		}
	}
	if r, err := ScanRustlsAEAD(path); err == nil {
		for _, m := range r.Methods {
			check("rustls method", m.VA, m.FileOff)
		}
	}
}

// TestLocators_GoAttachPointsAreInstructionBoundaries checks, on the Go
// executable AGENT_TRACE_LOCATOR_GO_BIN names (skipped without it), every
// attach point of tls-go-crypto as checkGoAttachPoints does: inside its
// function from the pclntab, at a run start of the function's own tables,
// a RET byte for each return.
func TestLocators_GoAttachPointsAreInstructionBoundaries(t *testing.T) {
	path := os.Getenv("AGENT_TRACE_LOCATOR_GO_BIN")
	if path == "" {
		t.Skip("AGENT_TRACE_LOCATOR_GO_BIN not set")
	}
	r, err := ScanGoTLS(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range []GoFunc{r.Write, r.Read} {
		t.Logf("%s entry %#x end %#x returns %x", fn.Name, fn.Entry.VA, fn.End, vas(fn.Returns))
	}
	checkGoAttachPoints(t, path, r)
}
