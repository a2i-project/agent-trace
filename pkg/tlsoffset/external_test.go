package tlsoffset

import (
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
