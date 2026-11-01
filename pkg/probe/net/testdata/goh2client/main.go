// Command goh2client is the Go TLS client of the tls-go-crypto tests (N-48):
// after a line on stdin (the start signal) it makes three requests over
// HTTP/2 to the base URL, trusting the PEM certificate file it is given,
// and reads each response whole. Standard library only.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Bodies, as the test computes them too.
const (
	smallBody = `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`
	largeLen  = 100000
)

func largeBody() string { return strings.Repeat("0123456789abcdef", largeLen/16) }

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: goh2client BASE_URL CERT_PEM")
		os.Exit(2)
	}
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		fmt.Fprintln(os.Stderr, "start signal:", err)
		os.Exit(1)
	}
	pem, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}}
	base := os.Args[1]
	for _, r := range []struct{ method, path, body string }{
		{"POST", "/v1internal:streamGenerateContent?alt=sse", smallBody},
		{"POST", "/v1internal:streamGenerateContent?alt=sse", largeBody()},
		{"GET", "/v1internal:loadCodeAssist", ""},
	} {
		var body io.Reader
		if r.body != "" {
			body = strings.NewReader(r.body)
		}
		req, err := http.NewRequest(r.method, base+r.path, body)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if _, err := io.ReadAll(resp.Body); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = resp.Body.Close()
		if resp.ProtoMajor != 2 {
			fmt.Fprintln(os.Stderr, "spoke", resp.Proto)
			os.Exit(1)
		}
	}
}
