package tlsoffset

import (
	"debug/elf"
	"fmt"
	"sort"
)

// ScanOpenSSLEx finds SSL_write_ex and SSL_read_ex candidates for the
// content method tls-openssl-ex (N-38). OpenSSL 1.1.1 and later write and
// read through these two whenever the caller wants the byte count through a
// pointer argument, as Rust's openssl crate does:
//
//	int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written)
//	int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *readbytes)
//
// A function with a symbol has that symbol as its only candidate. Otherwise
// the anchors are the function-name strings OpenSSL's error macros store:
// "ssl_write_internal" and "ssl_read_internal" name the internal functions
// every public write and read reaches; "SSL_write" and "SSL_read" name the
// two public functions that report errors themselves, which are therefore
// not the _ex ones. The candidates are the other direct callers of each
// internal function, and the functions that call or tail-jump to one of
// those (OpenSSL 3.2 and later build SSL_write_ex as a tail jump to
// SSL_write_ex2). They are ranked by evidence: a function whose address a
// relocation stores (a GOT slot or a method table, how Rust reaches it)
// first, then a direct caller over a wrapper, then the smaller function.
// Validation at run time decides among them (N-D4). ErrNoAnchor when an
// internal function's string or its function is missing.
func ScanOpenSSLEx(path string) (Result, error) {
	f, err := elf.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("open elf: %w", err)
	}
	defer func() { _ = f.Close() }()

	res := Result{BuildID: getBuildID(f)}
	for _, get := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		syms, err := get()
		if err != nil {
			continue
		}
		for _, s := range syms {
			if s.Value == 0 {
				continue
			}
			c := []Candidate{{VA: s.Value, FileOff: vaToFileOff(f, s.Value), Score: 100}}
			switch {
			case s.Name == "SSL_write_ex" && res.Write == nil:
				res.Write = c
			case s.Name == "SSL_read_ex" && res.Read == nil:
				res.Read = c
			}
		}
	}
	if res.Write != nil && res.Read != nil {
		return res, nil
	}

	im, err := newImage(f)
	if err != nil {
		return res, err
	}
	w, r, err := im.openSSLEx()
	if err != nil {
		return res, err
	}
	if res.Write == nil {
		res.Write = w
	}
	if res.Read == nil {
		res.Read = r
	}
	return res, nil
}

// Scores of the evidence ScanOpenSSLEx ranks by.
const (
	scoreAddressTaken = 1000
	scoreDirectCaller = 500
	scoreTailWrapper  = 300
	scoreCallWrapper  = 100
)

func (im *image) openSSLEx() (write, read []Candidate, err error) {
	strs, err := im.stringsAt("ssl_write_internal", "ssl_read_internal", "SSL_write", "SSL_read")
	if err != nil {
		return nil, nil, err
	}
	targets := map[uint64]bool{}
	for _, vas := range strs {
		for _, va := range vas {
			targets[va] = true
		}
	}
	refs, err := im.leaRefs(targets)
	if err != nil {
		return nil, nil, err
	}
	byString := im.functionsOf(refs)
	funcsOf := func(name string) map[uint64]bool {
		out := map[uint64]bool{}
		for _, va := range strs[name] {
			for fn := range byString[va] {
				out[fn] = true
			}
		}
		return out
	}
	wInternal, rInternal := funcsOf("ssl_write_internal"), funcsOf("ssl_read_internal")
	if len(wInternal) == 0 || len(rInternal) == 0 {
		return nil, nil, fmt.Errorf("%w: no function references \"ssl_write_internal\" and \"ssl_read_internal\" (no OpenSSL, or one without its function-name strings)", ErrNoAnchor)
	}
	wPublic, rPublic := funcsOf("SSL_write"), funcsOf("SSL_read")

	calls, err := im.branchRefs(setOf(wInternal, rInternal))
	if err != nil {
		return nil, nil, err
	}
	callers := im.functionsOf(calls)
	direct := func(internal, exclude map[uint64]bool) map[uint64]bool {
		out := map[uint64]bool{}
		for fn := range internal {
			for c := range callers[fn] {
				if !internal[c] && !exclude[c] {
					out[c] = true
				}
			}
		}
		return out
	}
	wDirect, rDirect := direct(wInternal, wPublic), direct(rInternal, rPublic)
	if len(wDirect) == 0 || len(rDirect) == 0 {
		return nil, nil, fmt.Errorf("%w: the OpenSSL internal functions have no caller besides SSL_write and SSL_read", ErrNoAnchor)
	}

	wraps, err := im.branchRefs(setOf(wDirect, rDirect))
	if err != nil {
		return nil, nil, err
	}
	score := map[uint64]int{}
	for fn := range setOf(wDirect, rDirect) {
		score[fn] = scoreDirectCaller
	}
	wWrap, rWrap := map[uint64]bool{}, map[uint64]bool{}
	for _, b := range wraps {
		start, _, ok := im.function(b.site)
		if !ok || score[start] == scoreDirectCaller || wInternal[start] || rInternal[start] || wPublic[start] || rPublic[start] {
			continue
		}
		s := scoreCallWrapper
		if b.op == 0xe9 {
			s = scoreTailWrapper
		}
		score[start] = max(score[start], s)
		if wDirect[b.target] {
			wWrap[start] = true
		} else {
			rWrap[start] = true
		}
	}
	all := setOf(wDirect, rDirect, wWrap, rWrap)
	taken := map[uint64]bool{}
	if err := im.forEachRelative(func(_, addend uint64) {
		if all[addend] {
			taken[addend] = true
		}
	}); err != nil {
		return nil, nil, err
	}
	rank := func(set map[uint64]bool) []Candidate {
		var out []Candidate
		for fn := range set {
			s := score[fn]
			if taken[fn] {
				s += scoreAddressTaken
			}
			if start, end, ok := im.function(fn); ok && start == fn {
				s -= min(int(end-start)/16, 99)
			}
			out = append(out, Candidate{VA: fn, FileOff: vaToFileOff(im.f, fn), Score: s})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Score != out[j].Score {
				return out[i].Score > out[j].Score
			}
			return out[i].VA < out[j].VA
		})
		return out
	}
	return rank(setOf(wDirect, wWrap)), rank(setOf(rDirect, rWrap)), nil
}
