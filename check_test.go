package main

import (
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetFor(t *testing.T) {
	tests := []struct {
		name string
		env  []string
		want string
	}{
		{"default port https", []string{"VAULT_ADDR=https://vault.example.com"}, "vault.example.com:443"},
		{"explicit port", []string{"VAULT_ADDR=http://100.64.0.1:8200"}, "100.64.0.1:8200"},
		{"no addr", nil, "127.0.0.1:8200"},
		{"unix socket", []string{"VAULT_ADDR=unix:///run/vault.sock"}, "/run/vault.sock"},
		{"https proxy", []string{"VAULT_ADDR=https://10.0.0.5:8200", "HTTPS_PROXY=http://127.0.0.1:3128"}, "10.0.0.5:8200 via 127.0.0.1:3128"},
		{"http proxy ignored for https", []string{"VAULT_ADDR=https://10.0.0.5:8200", "HTTP_PROXY=http://127.0.0.1:3128"}, "10.0.0.5:8200"},
		{"no_proxy bypass", []string{"VAULT_ADDR=https://vault.corp:8200", "HTTPS_PROXY=http://p:3128", "NO_PROXY=.corp"}, "vault.corp:8200"},
		{"vault proxy wins", []string{"VAULT_ADDR=https://v:8200", "HTTPS_PROXY=http://p:3128", "VAULT_PROXY_ADDR=socks5://s"}, "v:8200 via s:1080"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := targetFor(tc.env)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func vaultHandler(status int, body string) http.Handler {
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

const (
	activeBody = `{"initialized":true,"sealed":false,"standby":false,"version":"1.20.4"}`
	sealedBody = `{"initialized":true,"sealed":true,"standby":true,"version":"1.20.4"}`
)

func forbidden() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<html><body><h1>403 Forbidden</h1></body></html>"))
	})
}

func serve(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// closedURL returns a loopback URL with nothing listening on it.
func closedURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "http://" + addr
}

func writeContexts(t *testing.T, a *app, addrs map[string]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("contexts:\n")
	for name, addr := range addrs {
		b.WriteString("  " + name + ":\n    VAULT_ADDR: " + addr + "\n")
	}
	if err := os.WriteFile(a.configPath, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReachabilityBeforeExec(t *testing.T) {
	tests := []struct {
		name    string
		addr    func(t *testing.T) string
		wantErr string
	}{
		{"active", func(t *testing.T) string { return serve(t, vaultHandler(200, activeBody)) }, ""},
		{"sealed runs anyway", func(t *testing.T) string { return serve(t, vaultHandler(503, sealedBody)) }, ""},
		{"ingress 403", func(t *testing.T) string { return serve(t, forbidden()) }, "blocked: HTTP 403"},
		{"html 503", func(t *testing.T) string {
			return serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "maintenance", http.StatusServiceUnavailable)
			}))
		}, "not the Vault API"},
		{"nothing listening", closedURL, "unreachable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, _, call := newTestApp(t, "VCTX_CHECK_TIMEOUT=2s")
			writeContexts(t, a, map[string]string{"x": tc.addr(t)})
			err := a.run([]string{"x", "status"})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if call.argv0 != "" {
				t.Error("command ran although the check failed")
			}
		})
	}
}

func TestCheckDisabled(t *testing.T) {
	a, _, call := newTestApp(t)
	writeContexts(t, a, map[string]string{"x": closedURL(t)})
	if err := a.run([]string{"x", "status"}); err != nil || call.argv0 == "" {
		t.Fatalf("err = %v, ran = %v", err, call.argv0 != "")
	}
}

func TestTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(vaultHandler(200, activeBody))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{"VAULT_ADDR=" + srv.URL}
	if r := probe(t.Context(), env, defaultCheckTimeout); !isTLSError(r.err) {
		t.Errorf("without CA: err = %v, want a TLS verification error", r.err)
	}
	if r := probe(t.Context(), append(env, "VAULT_CACERT="+caFile), defaultCheckTimeout); r.err != nil {
		t.Errorf("with VAULT_CACERT: %v", r.err)
	}
	if r := probe(t.Context(), append(env, "VAULT_SKIP_VERIFY=true"), defaultCheckTimeout); r.err != nil {
		t.Errorf("with VAULT_SKIP_VERIFY: %v", r.err)
	}

	// An untrusted certificate is left for vault to report, so the command still runs.
	a, _, call := newTestApp(t, "VCTX_CHECK_TIMEOUT=2s")
	writeContexts(t, a, map[string]string{"x": srv.URL})
	if err := a.run([]string{"x", "status"}); err != nil || call.argv0 == "" {
		t.Fatalf("err = %v, ran = %v", err, call.argv0 != "")
	}

	plain := serve(t, vaultHandler(200, activeBody))
	r := probe(t.Context(), []string{"VAULT_ADDR=" + strings.Replace(plain, "http://", "https://", 1)}, defaultCheckTimeout)
	if got := reason(r.err); !strings.Contains(got, "does not speak TLS") {
		t.Errorf("https to plain http: %s", got)
	}
}

func TestCheckCommand(t *testing.T) {
	a, out, _ := newTestApp(t)
	writeContexts(t, a, map[string]string{
		"active":  serve(t, vaultHandler(200, activeBody)),
		"blocked": serve(t, forbidden()),
		"down":    closedURL(t),
		"sealed":  serve(t, vaultHandler(503, sealedBody)),
	})

	err := a.run([]string{"check"})
	if err == nil || !strings.Contains(err.Error(), "3 of 4") {
		t.Fatalf("err = %v", err)
	}
	want := map[string]string{
		"active":  "ok 1.20.4 active",
		"blocked": "blocked: HTTP 403 (text/html)",
		"down":    "unreachable:",
		"sealed":  "1.20.4 sealed",
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(want) {
		t.Fatalf("output:\n%s", out)
	}
	for _, line := range lines {
		name, _, _ := strings.Cut(line, " ")
		if !strings.Contains(line, want[name]) {
			t.Errorf("%s: %q, want %q", name, line, want[name])
		}
	}

	out.Reset()
	if err := a.run([]string{"check", "active"}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigErrorHasNoVPNHint(t *testing.T) {
	a, _, call := newTestApp(t, "VCTX_CHECK_TIMEOUT=2s")
	cfg := "contexts:\n  x:\n    VAULT_ADDR: " + serve(t, vaultHandler(200, activeBody)) + "\n    VAULT_CACERT: /nonexistent/ca.pem\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	err := a.run([]string{"x", "status"})
	if err == nil || !strings.Contains(err.Error(), "CA certificate") || strings.Contains(err.Error(), "VPN") {
		t.Fatalf("err = %v", err)
	}
	if call.argv0 != "" {
		t.Error("command ran despite a broken config")
	}
}

func TestServerTextSanitized(t *testing.T) {
	body := `{"initialized":true,"sealed":false,"version":"1.0\u001b]0;PWNED\u0007\u001b[2J"}`
	r := probe(t.Context(), []string{"VAULT_ADDR=" + serve(t, vaultHandler(200, body))}, defaultCheckTimeout)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if strings.ContainsAny(r.health.Version, "\x1b\x07") || r.health.Version != "1.0]0;PWNED[2J" {
		t.Errorf("version = %q", r.health.Version)
	}
	if got := sanitize(strings.Repeat("a", 50), 40); got != strings.Repeat("a", 40)+"…" {
		t.Errorf("long text: %q", got)
	}
}

func TestRedirectReported(t *testing.T) {
	addr := serve(t, http.RedirectHandler("https://sso.example.com/login", http.StatusFound))
	r := probe(t.Context(), []string{"VAULT_ADDR=" + addr}, defaultCheckTimeout)
	short, long := classify(r.err)
	if short != "blocked (HTTP 302)" || !strings.Contains(long, "redirect to sso.example.com") {
		t.Errorf("short %q, long %q", short, long)
	}
}
