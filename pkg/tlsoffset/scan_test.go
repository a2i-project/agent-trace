package tlsoffset

import (
	"debug/elf"
	"os"
	"os/exec"
	"testing"
)

func TestScanELF_Self(t *testing.T) {
	// Let's find something we know has symbols. The go test binary itself won't have SSL_write,
	// but let's test that it doesn't panic.
	path, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go command not found")
	}

	cands, buildID, err := ScanELF(path)
	if err != nil {
		t.Logf("Scan error (expected if no rodata): %v", err)
	}
	t.Logf("Go binary build ID: %s, candidates: %d", buildID, len(cands))
}

// TestScan_SymbolsOfSystemLibSSL checks that a library with symbols yields
// SSL_write and SSL_read as single, distinct candidates, at the file offsets
// debug/elf reports for the two symbols.
func TestScan_SymbolsOfSystemLibSSL(t *testing.T) {
	var lib string
	for _, p := range []string{"/lib/x86_64-linux-gnu/libssl.so.3", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "/usr/lib64/libssl.so.3"} {
		if _, err := os.Stat(p); err == nil {
			lib = p
			break
		}
	}
	if lib == "" {
		t.Skip("no libssl.so.3")
	}
	r, err := Scan(lib)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(r.Write) != 1 || len(r.Read) != 1 {
		t.Fatalf("Write = %v, Read = %v, want one symbol each", r.Write, r.Read)
	}
	if r.Write[0].FileOff == r.Read[0].FileOff {
		t.Fatalf("SSL_write and SSL_read at the same offset %#x", r.Write[0].FileOff)
	}
	f, err := elf.Open(lib)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	syms, err := f.DynamicSymbols()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{}
	for _, s := range syms {
		if s.Name == "SSL_write" || s.Name == "SSL_read" {
			want[s.Name] = vaToFileOff(f, s.Value)
		}
	}
	if r.Write[0].FileOff != want["SSL_write"] || r.Read[0].FileOff != want["SSL_read"] {
		t.Errorf("offsets write %#x read %#x, want %#x %#x", r.Write[0].FileOff, r.Read[0].FileOff, want["SSL_write"], want["SSL_read"])
	}

	w, _, err := ScanELF(lib)
	if err != nil || len(w) != 1 || w[0] != r.Write[0] {
		t.Errorf("ScanELF = %v, %v; want the SSL_write candidate of Scan", w, err)
	}
}
