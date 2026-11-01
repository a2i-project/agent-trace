// Command gotls is the Go program the tls-go-crypto locator's tests build
// (N-47): it links crypto/tls.(*Conn).Write and (*Conn).Read. It is never
// run by the tests.
package main

import (
	"crypto/tls"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		return
	}
	c, err := tls.Dial("tcp", os.Args[1], &tls.Config{ServerName: "localhost"})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		fmt.Println(err)
		return
	}
	b := make([]byte, 512)
	n, _ := c.Read(b)
	fmt.Println(n)
}
