package tlsparse

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// buildClientHello assembles a minimal but structurally valid TLS 1.2-style
// ClientHello record wrapping the given extensions (already TLV-encoded).
func buildClientHello(extensions []byte) []byte {
	body := []byte{}
	body = append(body, 0x03, 0x03)             // legacy client version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session id len 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites: len 2, one suite
	body = append(body, 0x01, 0x00)             // compression methods: len 1, null

	if extensions != nil {
		extLen := len(extensions)
		body = append(body, byte(extLen>>8), byte(extLen))
		body = append(body, extensions...)
	}

	hs := []byte{handshakeTypeClientHello}
	hsLen := len(body)
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	hs = append(hs, body...)

	rec := []byte{recordTypeHandshake, 0x03, 0x01}
	recLen := len(hs)
	rec = append(rec, byte(recLen>>8), byte(recLen))
	rec = append(rec, hs...)
	return rec
}

func sniExtension(host string) []byte {
	entry := []byte{0x00} // name_type host_name
	entry = append(entry, byte(len(host)>>8), byte(len(host)))
	entry = append(entry, host...)
	list := []byte{byte(len(entry) >> 8), byte(len(entry))}
	list = append(list, entry...)
	ext := []byte{0x00, 0x00} // extension type SNI
	ext = append(ext, byte(len(list)>>8), byte(len(list)))
	ext = append(ext, list...)
	return ext
}

func alpnExtension(protos ...string) []byte {
	var list []byte
	for _, p := range protos {
		list = append(list, byte(len(p)))
		list = append(list, p...)
	}
	data := []byte{byte(len(list) >> 8), byte(len(list))}
	data = append(data, list...)
	ext := []byte{0x00, 0x10} // extension type ALPN
	ext = append(ext, byte(len(data)>>8), byte(len(data)))
	ext = append(ext, data...)
	return ext
}

func TestParseClientHello_SNIPresent(t *testing.T) {
	data := buildClientHello(sniExtension("api.example.com"))
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ServerName != "api.example.com" {
		t.Errorf("ServerName = %q, want %q", got.ServerName, "api.example.com")
	}
}

func TestParseClientHello_SNIAbsent(t *testing.T) {
	data := buildClientHello(alpnExtension("http/1.1"))
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ServerName != "" {
		t.Errorf("ServerName = %q, want empty", got.ServerName)
	}
}

func TestParseClientHello_ALPN_H2(t *testing.T) {
	data := buildClientHello(alpnExtension("h2", "http/1.1"))
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", got.ALPN)
	}
}

func TestParseClientHello_ALPN_HTTP11Only(t *testing.T) {
	data := buildClientHello(alpnExtension("http/1.1"))
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got.ALPN, []string{"http/1.1"}) {
		t.Errorf("ALPN = %v, want [http/1.1]", got.ALPN)
	}
}

func TestParseClientHello_SNIAndALPNTogether(t *testing.T) {
	ext := append(append([]byte{}, sniExtension("example.com")...), alpnExtension("h2")...)
	data := buildClientHello(ext)
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com", got.ServerName)
	}
	if !reflect.DeepEqual(got.ALPN, []string{"h2"}) {
		t.Errorf("ALPN = %v, want [h2]", got.ALPN)
	}
}

func TestParseClientHello_NonTLSFirstBytes(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\n\r\n")
	_, err := ParseClientHello(data)
	if !errors.Is(err, ErrNotClientHello) {
		t.Fatalf("err = %v, want ErrNotClientHello", err)
	}
}

func TestParseClientHello_TruncatedRecord(t *testing.T) {
	full := buildClientHello(sniExtension("example.com"))
	// Cut off inside the fixed-size prefix (well before extensions begin).
	truncated := full[:10]
	_, err := ParseClientHello(truncated)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
}

func TestParseClientHello_SplitAtCaptureLimit(t *testing.T) {
	// SNI first, then a second (large-ish) extension, so cutting the buffer
	// after SNI but mid the second extension simulates net.bpf.c's
	// 1024-byte NET_HELLO capture limit landing inside the extensions
	// block. Truncation there must not be an error and must not lose the
	// SNI already parsed.
	big := alpnExtension("h2", "http/1.1", "spdy/3.1", "http/1.0")
	ext := append(append([]byte{}, sniExtension("example.com")...), big...)
	full := buildClientHello(ext)

	cut := len(full) - 3 // land inside the trailing extension's data
	got, err := ParseClientHello(full[:cut])
	if err != nil {
		t.Fatalf("unexpected error on extension-block truncation: %v", err)
	}
	if got.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com (should survive truncation of a later extension)", got.ServerName)
	}
}

func TestParseClientHello_NoExtensions(t *testing.T) {
	data := buildClientHello(nil)
	got, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ServerName != "" || got.ALPN != nil {
		t.Errorf("got %+v, want zero-value ClientHello", got)
	}
}

// paddingExtension returns a padding extension (RFC 7685) of n zero bytes, the
// filler a client adds to reach a size, used here to push SNI back.
func paddingExtension(n int) []byte {
	ext := []byte{0x00, 0x15, byte(n >> 8), byte(n)}
	return append(ext, make([]byte, n)...)
}

// fragment re-frames a single-record ClientHello as consecutive handshake
// records whose payloads hold at most size bytes each, as a client does with
// a hello larger than a record or one fragmented on purpose.
func fragment(record []byte, size int) []byte {
	msg := record[5:]
	var out []byte
	for len(msg) > 0 {
		n := min(size, len(msg))
		out = append(out, recordTypeHandshake, 0x03, 0x01, byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

// TestParseClientHello_SNIPastTheFirstKiB is the case N-31 exists for: a
// 2 KiB ClientHello, the size a post-quantum key share gives, whose SNI
// extension sits past byte 1024, as Chrome's extension permutation puts it
// about half the time (measured on Chrome 151). Whole, split across records,
// and split across records with a short final read.
func TestParseClientHello_SNIPastTheFirstKiB(t *testing.T) {
	const host = "api.example.com"
	ext := append(append(paddingExtension(1950), sniExtension(host)...), alpnExtension("h2", "http/1.1")...)
	whole := buildClientHello(ext)
	if len(whole) < 2000 || len(whole) > 2200 {
		t.Fatalf("synthetic hello is %d bytes, want about 2 KiB", len(whole))
	}
	if i := bytes.Index(whole, []byte(host)); i <= 1024 {
		t.Fatalf("SNI name at byte %d, want past 1024", i)
	}

	tests := []struct {
		name     string
		data     []byte
		wantSNI  string
		complete bool
	}{
		{"one record", whole, host, true},
		{"one record cut at 1 KiB loses the name", whole[:1024], "", false},
		{"two records", fragment(whole, 1200), host, true},
		{"many small records", fragment(whole, 100), host, true},
		{"one-byte records", fragment(whole, 1), host, true},
		{"records then trailing bytes", append(fragment(whole, 1500), 0x17, 0x03, 0x03, 0x00, 0x01, 0xaa), host, true},
		{"second record cut short", fragment(whole, 1500)[:1700], "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseClientHello(tt.data)
			if err != nil {
				t.Fatalf("ParseClientHello: %v", err)
			}
			if got.ServerName != tt.wantSNI {
				t.Errorf("ServerName = %q, want %q", got.ServerName, tt.wantSNI)
			}
			if tt.wantSNI != "" && !reflect.DeepEqual(got.ALPN, []string{"h2", "http/1.1"}) {
				t.Errorf("ALPN = %v, want [h2 http/1.1]", got.ALPN)
			}
			if c := ClientHelloComplete(tt.data); c != tt.complete {
				t.Errorf("ClientHelloComplete = %v, want %v", c, tt.complete)
			}
		})
	}
}

func TestClientHelloComplete(t *testing.T) {
	whole := buildClientHello(sniExtension("example.com"))
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"whole record", whole, true},
		{"record header only", whole[:5], false},
		{"one byte short", whole[:len(whole)-1], false},
		{"not TLS", []byte("GET / HTTP/1.1\r\n"), false},
		{"empty", nil, false},
		{"application data record", []byte{0x17, 0x03, 0x03, 0x00, 0x00}, false},
	}
	for _, tt := range tests {
		if got := ClientHelloComplete(tt.data); got != tt.want {
			t.Errorf("%s: ClientHelloComplete = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// FuzzParseClientHello checks that no input panics either entry point, and
// that splitting a hello across records never changes what it parses to.
func FuzzParseClientHello(f *testing.F) {
	whole := buildClientHello(append(sniExtension("example.com"), alpnExtension("h2")...))
	f.Add(whole, 7)
	f.Add(whole[:20], 3)
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00}, 1)
	f.Fuzz(func(t *testing.T, data []byte, size int) {
		got, err := ParseClientHello(data)
		_ = ClientHelloComplete(data)
		if err != nil || !ClientHelloComplete(data) || len(data) < 9 || size < 1 || size > 1<<14 {
			return
		}
		n := int(data[3])<<8 | int(data[4])
		if 5+n > len(data) || int(data[6])<<16|int(data[7])<<8|int(data[8]) != n-4 {
			return // only a single complete record is re-framed
		}
		split, err := ParseClientHello(fragment(data[:5+n], size))
		if err != nil || split.ServerName != got.ServerName || !reflect.DeepEqual(split.ALPN, got.ALPN) {
			t.Fatalf("fragmented: %+v, %v; whole: %+v", split, err, got)
		}
	})
}
