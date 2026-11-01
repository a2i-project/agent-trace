package tlsoffset

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// buildGoTLS builds testdata/gotls with the extra go build arguments into
// dir, or skips when the build needs what the machine lacks (a C linker for
// external linking).
func buildGoTLS(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", append(append([]string{"build", "-o", out}, args...), "./testdata/gotls")...)
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GOARCH=amd64", "GOOS=linux")
	if b, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(strings.Join(args, " "), "external") {
			t.Skipf("external linking unavailable: %v\n%s", err, b)
		}
		t.Fatalf("go build %v: %v\n%s", args, err, b)
	}
	return out
}

var objdumpRet = regexp.MustCompile(`\s0x([0-9a-f]+)\s+c3\s+RET\b`)
var objdumpText = regexp.MustCompile(`(?m)^TEXT \S+\(SB\)`)
var objdumpAddr = regexp.MustCompile(`\s0x([0-9a-f]+)\s`)

// objdumpFunc disassembles one function of an executable with symbols with
// go tool objdump (part of the toolchain) and returns its first address and
// the address of every RET.
func objdumpFunc(t *testing.T, bin, name string) (uint64, []uint64) {
	t.Helper()
	out, err := exec.Command("go", "tool", "objdump", "-s", "^"+regexp.QuoteMeta(name)+"$", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("go tool objdump: %v\n%s", err, out)
	}
	if n := len(objdumpText.FindAll(out, -1)); n != 1 {
		t.Fatalf("objdump found %d functions named %s", n, name)
	}
	parse := func(h string) uint64 {
		v, _ := strconv.ParseUint(h, 16, 64)
		return v
	}
	first := objdumpAddr.FindSubmatch(out)
	if first == nil {
		t.Fatalf("no instruction in the objdump of %s", name)
	}
	var rets []uint64
	for _, m := range objdumpRet.FindAllSubmatch(out, -1) {
		rets = append(rets, parse(string(m[1])))
	}
	return parse(string(first[1])), rets
}

// The locator finds (*Conn).Write and (*Conn).Read and every RET in them in
// a Go program built here, linked internally as an executable and as a PIE,
// and externally as a PIE, each with and without symbols: the same entries
// and returns as go tool objdump disassembles from the build with symbols,
// and the stripped build gives the same addresses.
func TestScanGoTLS_MatchesTheDisassembly(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []struct {
		name string
		args []string
	}{
		{"exe", nil},
		{"pie", []string{"-buildmode=pie"}},
		{"pie-external", []string{"-buildmode=pie", "-ldflags=-linkmode=external"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			full := buildGoTLS(t, dir, mode.name, mode.args...)
			strippedArgs := append([]string{}, mode.args...)
			if len(strippedArgs) > 0 && strings.HasPrefix(strippedArgs[len(strippedArgs)-1], "-ldflags=") {
				strippedArgs[len(strippedArgs)-1] += " -s -w"
			} else {
				strippedArgs = append(strippedArgs, "-ldflags=-s -w")
			}
			stripped := buildGoTLS(t, dir, mode.name+"-s", strippedArgs...)
			got, err := ScanGoTLS(full)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(got.GoVersion, "go1.") {
				t.Errorf("GoVersion %q", got.GoVersion)
			}
			for _, fn := range []GoFunc{got.Write, got.Read} {
				entry, rets := objdumpFunc(t, full, fn.Name)
				if fn.Entry.VA != entry || !reflect.DeepEqual(vas(fn.Returns), rets) {
					t.Errorf("%s: entry %#x returns %x, objdump %#x %x", fn.Name, fn.Entry.VA, vas(fn.Returns), entry, rets)
				}
			}
			s, err := ScanGoTLS(stripped)
			if err != nil {
				t.Fatalf("stripped: %v", err)
			}
			f, _ := elf.Open(stripped)
			if syms, _ := f.Symbols(); len(syms) > 0 {
				t.Errorf("the stripped build has %d symbols", len(syms))
			}
			_ = f.Close()
			if fmt.Sprint(s.Write.Entry.VA, vas(s.Write.Returns), s.Read.Entry.VA, vas(s.Read.Returns)) !=
				fmt.Sprint(got.Write.Entry.VA, vas(got.Write.Returns), got.Read.Entry.VA, vas(got.Read.Returns)) {
				t.Errorf("stripped build: %+v, with symbols %+v", s, got)
			}
			checkGoAttachPoints(t, stripped, s)
		})
	}
}

// checkGoAttachPoints checks every attach point of a tls-go-crypto result:
// the entry and each return lie inside their function in an executable
// segment, their file offsets map back to them, each return is a RET byte,
// and each is at an instruction boundary: the start of a run of the
// function's stack-pointer or line table, or reached from one through no-op
// instructions only.
func checkGoAttachPoints(t *testing.T, path string, r GoTLSResult) {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	p, err := findPclntab(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.textStart, err = goTextStart(f, p); err != nil {
		t.Fatal(err)
	}
	for _, fn := range []GoFunc{r.Write, r.Read} {
		if fn.Entry.VA >= fn.End || !executableVA(f, fn.Entry.VA) || vaToFileOff(f, fn.Entry.VA) != fn.Entry.FileOff {
			t.Errorf("%s entry %#x (file %#x) misplaced", fn.Name, fn.Entry.VA, fn.Entry.FileOff)
		}
		// The function's runs, from its own _func record.
		starts := map[uint64]bool{fn.Entry.VA: true}
		for _, pc := range pcStartsOf(t, p, fn) {
			starts[pc] = true
		}
		im := &image{f: f}
		for _, c := range fn.Returns {
			b, err := im.readVA(c.VA, 1)
			if err != nil || b[0] != 0xc3 || c.VA <= fn.Entry.VA || c.VA >= fn.End || !executableVA(f, c.VA) || vaToFileOff(f, c.VA) != c.FileOff || !reachable(im, starts, c.VA) {
				t.Errorf("%s return %#x (file %#x) is not a RET at an instruction boundary inside the function", fn.Name, c.VA, c.FileOff)
			}
		}
	}
}

// reachable reports whether va is a run start, or follows one through no-op
// instructions only.
func reachable(im *image, starts map[uint64]bool, va uint64) bool {
	for s := range starts {
		if s > va || va-s > retWalk {
			continue
		}
		b, err := im.readVA(s, int(va-s))
		if err != nil {
			continue
		}
		at := 0
		for at < len(b) {
			n := nopLen(b[at:])
			if n == 0 {
				break
			}
			at += n
		}
		if at == len(b) {
			return true
		}
	}
	return false
}

// pcStartsOf returns the start of every run of fn's pc-line table, a table
// the locator does not read: each is an instruction boundary.
func pcStartsOf(t *testing.T, p *gopcln, fn GoFunc) []uint64 {
	t.Helper()
	r := &winReader{sec: p.sec}
	ftab := p.off + p.ftab
	for i := 0; i < p.nfunc; i++ {
		entry, _ := r.u32(ftab + 8*i)
		if p.textStart+uint64(entry) != fn.Entry.VA {
			continue
		}
		funcoff, _ := r.u32(ftab + 8*i + 4)
		fo := ftab + int(funcoff)
		var out []uint64
		for _, field := range []int{16, 24} { // pcsp, pcln
			off, _ := r.u32(fo + field)
			runs, err := p.pcValues(fn.Entry.VA, int(off))
			if err != nil {
				t.Fatal(err)
			}
			for _, run := range runs {
				out = append(out, run.start)
			}
		}
		return out
	}
	t.Fatalf("%s not in the function table", fn.Name)
	return nil
}

// A file that is no Go executable, or a Go executable without crypto/tls,
// is refused with ErrNoAnchor.
func TestScanGoTLS_Refuses(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nfunc main() { println(\"hi\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module notls\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "notls")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	if _, err := ScanGoTLS(bin); !errors.Is(err, ErrNoAnchor) || !strings.Contains(err.Error(), GoTLSWrite) {
		t.Errorf("a Go program without crypto/tls: %v", err)
	}
	if _, err := ScanGoTLS("/bin/sh"); !errors.Is(err, ErrNoAnchor) {
		t.Errorf("/bin/sh: %v", err)
	}
}
