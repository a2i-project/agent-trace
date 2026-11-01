package net

import (
	"encoding/binary"
	"fmt"
	stdnet "net"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// h2Frames is what an h2 client writes first: the preface, then a SETTINGS
// frame (type 4, empty), then a HEADERS frame on stream 0, which breaks the
// protocol.
var h2Frames = [][]byte{
	append(append([]byte{}, h2ClientPreface...), 0, 0, 0, 4, 0, 0, 0, 0, 0),
	{0, 0, 0, 1, 4, 0, 0, 0, 1},
	{0, 0, 0, 0, 1, 0, 0, 0, 0},
}

// An h2 connection's frames count under the h2 counters (N-33); a frame that
// breaks the protocol ends the direction, counted in H2Unparsed (N-46).
func TestHandleSSLFrame_H2ConnectionIsCounted(t *testing.T) {
	o := newTestObserver()
	key := sslKey{tgid: 1, ssl: 7}
	for _, f := range h2Frames {
		o.handleSSLFrame(key, f, 0, time.Now())
	}
	if o.coverage.H2Preface != 1 {
		t.Errorf("H2Preface = %d, want 1", o.coverage.H2Preface)
	}
	if o.coverage.FramesH2 != len(h2Frames) {
		t.Errorf("FramesH2 = %d, want %d", o.coverage.FramesH2, len(h2Frames))
	}
	if o.coverage.WithContent != 0 || o.coverage.H2Unparsed != 1 {
		t.Errorf("WithContent = %d, H2Unparsed = %d, want 0 and 1", o.coverage.WithContent, o.coverage.H2Unparsed)
	}
	select {
	case ev := <-o.events:
		t.Errorf("an h2 connection emitted %+v", ev)
	default:
	}
}

// An HTTP/1.1 connection, whatever its ClientHello offered, parses as before
// and counts nothing under h2. An SSL* reused for HTTP/1.1 after an h2
// connection: its first request breaks the h2 framing and is lost, and the
// next one parses as HTTP/1.1 (N-46).
func TestHandleSSLFrame_HTTP1ConnectionIsNotH2(t *testing.T) {
	o := newTestObserver()
	key := sslKey{tgid: 1, ssl: 8}
	req := []byte("GET /a HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	o.handleSSLFrame(key, req, 0, time.Now())
	if o.coverage.H2Preface != 0 || o.coverage.FramesH2 != 0 {
		t.Errorf("H2Preface = %d, FramesH2 = %d on HTTP/1.1, want 0 and 0", o.coverage.H2Preface, o.coverage.FramesH2)
	}
	if o.coverage.WithContent != 1 {
		t.Errorf("WithContent = %d, want 1", o.coverage.WithContent)
	}
	<-o.events

	reused := sslKey{tgid: 1, ssl: 9}
	o.handleSSLFrame(reused, h2Frames[0], 0, time.Now())
	o.handleSSLFrame(reused, req, 0, time.Now())
	o.handleSSLFrame(reused, req, 0, time.Now())
	if o.coverage.FramesH2 != 2 {
		t.Errorf("FramesH2 = %d, want 2: the preface and the request that ended the h2 direction", o.coverage.FramesH2)
	}
	if o.coverage.WithContent != 2 || o.coverage.H2Unparsed != 1 {
		t.Errorf("WithContent = %d, H2Unparsed = %d, want 2 and 1", o.coverage.WithContent, o.coverage.H2Unparsed)
	}
}

// Every field of the capture's net content record is copied from the
// correlator's field of the same name, so no counter is left at zero by an
// omission.
func TestNetContentCounts_CopiesEveryField(t *testing.T) {
	var cov Coverage
	cv := reflect.ValueOf(&cov).Elem()
	want := models.NetContentCounts{}
	wv := reflect.ValueOf(&want).Elem()
	for i := 0; i < wv.NumField(); i++ {
		name := wv.Type().Field(i).Name
		f := cv.FieldByName(name)
		if !f.IsValid() {
			t.Fatalf("Coverage has no field %s", name)
		}
		v := int64(i + 1)
		switch f.Kind() {
		case reflect.Int:
			f.SetInt(v)
		case reflect.Uint64:
			f.SetUint(uint64(v))
		case reflect.Map:
			f.Set(reflect.ValueOf(map[string]int{name: int(v)}))
		}
		switch wv.Field(i).Kind() {
		case reflect.Int:
			wv.Field(i).SetInt(v)
		case reflect.Uint64:
			wv.Field(i).SetUint(uint64(v))
		case reflect.Map:
			wv.Field(i).Set(reflect.ValueOf(map[string]int{name: int(v)}))
		}
	}
	if got := netContentCounts(cov); !reflect.DeepEqual(*got, want) {
		t.Errorf("netContentCounts = %+v, want %+v", *got, want)
	}
}

// The diagnostics report the net ring and drops split by ring, with the
// legacy sum unchanged; the TLS ring and tracked set appear only with
// content capture, and the SSL_write counts only with their uretprobe.
func TestCaptureCoverage_DiagnosticsSplitDropsByRing(t *testing.T) {
	o := &Observer{netRingSize: 1 << 20, coverage: Coverage{Connections: 3, ContentUnsupported: 1}}
	o.finalNetDrops.Store(4)
	o.finalTLSDrops.Store(3)
	o.finalReadDrops.Store(2)
	o.kernelCountersFinal.Store(true)
	o.netRing.observe(&ringbuf.Record{RawSample: make([]byte, 60), Remaining: 100})

	pc := o.CaptureCoverage()
	if pc.RingbufDrops != 7 {
		t.Errorf("RingbufDrops = %d, want the sum 7", pc.RingbufDrops)
	}
	d := pc.Diagnostics
	if d == nil {
		t.Fatal("Diagnostics = nil")
	}
	want := models.RingStats{SizeBytes: 1 << 20, PeakBytes: 100 + 8 + 64, Records: 1, Drops: 4}
	if got := d.Rings["net_events"]; !reflect.DeepEqual(got, want) {
		t.Errorf("net_events = %+v, want %+v", got, want)
	}
	if _, ok := d.Rings["ssl_events"]; ok {
		t.Error("ssl_events reported without content capture")
	}
	if d.NetContent == nil || d.NetContent.Connections != 3 || d.NetContent.ContentUnsupported != 1 {
		t.Errorf("NetContent = %+v, want the correlator's counts", d.NetContent)
	}

	o.tlsTracked = &trackedCounter{capacity: 4096, final: &models.TrackedSetStats{Capacity: 4096, Peak: 2, AtStop: 1}}
	o.sslRingSize = 4 << 20
	d = o.CaptureCoverage().Diagnostics
	ssl, ok := d.Rings["ssl_events"]
	if !ok || ssl.Drops != 3 || ssl.ReadDrops == nil || *ssl.ReadDrops != 2 || ssl.SizeBytes != 4<<20 {
		t.Errorf("ssl_events = %+v (read drops %v), want drops 3, read drops 2, size 4 MiB", ssl, ssl.ReadDrops)
	}
	if got := d.TrackedSets["tls"]; got.Peak != 2 || got.AtStop != 1 {
		t.Errorf("tracked tls = %+v, want the snapshot", got)
	}
	if d.SSLWrites != nil {
		t.Errorf("SSLWrites = %+v without the uretprobe, want nil (not measured)", d.SSLWrites)
	}

	// With the uretprobe attached, the snapshot Stop took is reported (N-36).
	w := &models.SSLWriteCounts{Calls: 5, Partial: 1, Failed: 2, BytesRequested: 900, BytesWritten: 500}
	o.sslWrites = &sslWriteMeter{snapped: true, final: w}
	if got := o.CaptureCoverage().Diagnostics.SSLWrites; got == nil || *got != *w {
		t.Errorf("SSLWrites = %+v, want %+v", got, w)
	}
	o.sslWrites = &sslWriteMeter{snapped: true}
	if got := o.CaptureCoverage().Diagnostics.SSLWrites; got != nil {
		t.Errorf("SSLWrites = %+v after a failed snapshot, want nil", got)
	}
}

// TestObserver_NetRingHighWaterMark opens connections before the reader
// starts, so the first read sees every connect record in the ring: the mark
// must cover at least their bytes (N-33).
func TestObserver_NetRingHighWaterMark(t *testing.T) {
	skipUnprivileged(t)

	const conns = 32
	port := sinks(t, 1)[0]
	obs, err := New(Config{TrackedPID: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var open []stdnet.Conn
	for i := 0; i < conns; i++ {
		c, err := stdnet.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		open = append(open, c)
	}
	obs.Start()
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for _, c := range open {
		_ = c.Close()
	}
	for range obs.Events() {
	}

	pc := obs.CaptureCoverage()
	ring := pc.Diagnostics.Rings["net_events"]
	record := uint64(8 + (binary.Size(bpfNetEventHdr{})+7)&^7)
	t.Logf("net_events ring: %+v, connect record %d bytes", ring, record)
	if ring.PeakBytes < conns*record {
		t.Errorf("PeakBytes = %d, want at least the %d bytes of %d connect records", ring.PeakBytes, conns*record, conns)
	}
	if ring.Records < conns || ring.SizeBytes != 1<<20 || ring.Drops != 0 {
		t.Errorf("Records = %d, SizeBytes = %d, Drops = %d, want at least %d, 1 MiB and 0", ring.Records, ring.SizeBytes, ring.Drops, conns)
	}
	if c := pc.Diagnostics.NetContent; c == nil || c.Connections < conns {
		t.Errorf("NetContent = %+v, want at least %d connections", c, conns)
	}
}

// TestObserver_NetTrackedSetPeak keeps a known number of children alive at
// once: the seeded test process and 24 children make a peak of 25, and once
// they are reaped only the test process is left (N-33).
func TestObserver_NetTrackedSetPeak(t *testing.T) {
	skipUnprivileged(t)

	const children = 24
	obs, err := New(Config{TrackedPID: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	var procs []*exec.Cmd
	for i := 0; i < children; i++ {
		c := exec.Command("/bin/sleep", "5")
		if err := c.Start(); err != nil {
			t.Fatalf("spawn sleep: %v", err)
		}
		procs = append(procs, c)
	}
	running := obs.netTracked.stats()
	inMap := 0
	var k uint32
	var v uint8
	it := obs.objs.TrackedPids.Iterate()
	for it.Next(&k, &v) {
		inMap++
	}
	for _, c := range procs {
		_ = c.Process.Kill()
		_ = c.Wait()
	}
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for range obs.Events() {
	}

	if running.AtStop != int64(inMap) || inMap != children+1 {
		t.Errorf("while running: counted %d entries, the map holds %d, want %d", running.AtStop, inMap, children+1)
	}
	got := obs.CaptureCoverage().Diagnostics.TrackedSets["net"]
	want := models.TrackedSetStats{Capacity: 4096, Peak: children + 1, AtStop: 1}
	if got != want {
		t.Errorf("tracked set = %+v, want %+v", got, want)
	}
}

// BenchmarkHandleSSLFrame_HTTP1 is the correlator's cost per HTTP/1.1 write
// frame, the h2 preface check included.
func BenchmarkHandleSSLFrame_HTTP1(b *testing.B) {
	o := newTestObserver()
	o.events = make(chan models.GroundTruthEvent)
	req := []byte("POST /v1/messages HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\n{}")
	key := sslKey{tgid: 1, ssl: 1}
	for b.Loop() {
		o.handleSSLFrame(key, req, 0, time.Time{})
	}
}
