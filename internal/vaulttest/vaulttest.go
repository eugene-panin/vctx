// Package vaulttest provides stand-ins for Vault servers and proxies in tests.
package vaulttest

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// sys/health bodies of an active and a sealed node.
const (
	ActiveBody = `{"initialized":true,"sealed":false,"standby":false,"version":"1.20.4"}`
	SealedBody = `{"initialized":true,"sealed":true,"standby":true,"version":"1.20.4"}`
)

// Handler answers sys/health with status and body, and 404 elsewhere.
func Handler(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	})
}

// Forbidden answers like an ingress rejecting the client's IP.
func Forbidden() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<html><body><h1>403 Forbidden</h1></body></html>"))
	})
}

// Serve runs h on a loopback server for the rest of the test and returns its URL.
func Serve(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// ClosedURL is a loopback URL nothing listens on: port 1 (tcpmux) is
// privileged and unused, unlike a freed ephemeral port another test may take.
func ClosedURL(*testing.T) string {
	return "http://127.0.0.1:1"
}

// ConnectProxy tunnels CONNECT requests to whatever host they name.
func ConnectProxy(t *testing.T) string {
	t.Helper()
	return Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		go func() { io.Copy(upstream, buf); upstream.Close() }()
		io.Copy(conn, upstream)
		conn.Close()
	}))
}

// RawProxy answers every request with statusLine, as proxies with their own
// reason phrases do ("504 Gateway Time-out" from nginx, "502 Proxy Error" from Apache).
func RawProxy(t *testing.T, statusLine string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				http.ReadRequest(bufio.NewReader(conn))
				io.WriteString(conn, "HTTP/1.1 "+statusLine+"\r\nContent-Length: 0\r\n\r\n")
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}
