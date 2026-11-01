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
