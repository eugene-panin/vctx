package main

import (
	"crypto/tls"
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

	tea "github.com/charmbracelet/bubbletea"
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

// probeEnv probes the target env resolves to, as vctx does before running vault.
func probeEnv(t *testing.T, env []string) probeResult {
	t.Helper()
	tg, err := targetFor(env)
	if err != nil {
		return probeResult{err: err}
	}
	return probe(t.Context(), tg, env, defaultCheckTimeout)
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

// closedURL returns a loopback URL nothing listens on: port 1 (tcpmux) is
// privileged and unused, unlike a freed ephemeral port another test may take.
func closedURL(*testing.T) string {
	return "http://127.0.0.1:1"
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
	if r := probeEnv(t, env); !isTLSError(r.err) {
		t.Errorf("without CA: err = %v, want a TLS verification error", r.err)
	}
	if r := probeEnv(t, append(env, "VAULT_CACERT="+caFile)); r.err != nil {
		t.Errorf("with VAULT_CACERT: %v", r.err)
	}
	if r := probeEnv(t, append(env, "VAULT_SKIP_VERIFY=true")); r.err != nil {
		t.Errorf("with VAULT_SKIP_VERIFY: %v", r.err)
	}

	// An untrusted certificate is left for vault to report, so the command still runs.
	a, _, call := newTestApp(t, "VCTX_CHECK_TIMEOUT=2s")
	writeContexts(t, a, map[string]string{"x": srv.URL})
	if err := a.run([]string{"x", "status"}); err != nil || call.argv0 == "" {
		t.Fatalf("err = %v, ran = %v", err, call.argv0 != "")
	}

	plain := serve(t, vaultHandler(200, activeBody))
	r := probeEnv(t, []string{"VAULT_ADDR=" + strings.Replace(plain, "http://", "https://", 1)})
	if _, got := classify(r.err); !strings.Contains(got, "does not speak TLS") {
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
	r := probeEnv(t, []string{"VAULT_ADDR=" + serve(t, vaultHandler(200, body))})
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
	r := probeEnv(t, []string{"VAULT_ADDR=" + addr})
	short, long := classify(r.err)
	if short != "blocked (HTTP 302)" || !strings.Contains(long, "redirect to sso.example.com") {
		t.Errorf("short %q, long %q", short, long)
	}
}

func TestTLSAlertLeftToVault(t *testing.T) {
	srv := httptest.NewUnstartedServer(vaultHandler(200, activeBody))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	env := []string{"VAULT_ADDR=" + srv.URL, "VAULT_SKIP_VERIFY=true"}
	r := probeEnv(t, env)
	if !isTLSError(r.err) || networkProblem(r.err) {
		t.Fatalf("err = %v: tls %v, network %v", r.err, isTLSError(r.err), networkProblem(r.err))
	}
	if short, long := classify(r.err); short != "tls error" || strings.Contains(long, "unreachable") {
		t.Errorf("short %q, long %q", short, long)
	}

	a, _, call := newTestApp(t, "VCTX_CHECK_TIMEOUT=2s")
	cfg := "contexts:\n  x:\n    VAULT_ADDR: " + srv.URL + "\n    VAULT_SKIP_VERIFY: \"true\"\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"x", "status"}); err != nil || call.argv0 == "" {
		t.Fatalf("vault not started: err = %v", err)
	}
}

func TestAgentAddrWins(t *testing.T) {
	got, err := targetFor([]string{"VAULT_ADDR=https://vault:8200", "VAULT_AGENT_ADDR=http://127.0.0.1:8100"})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "127.0.0.1:8100" {
		t.Errorf("target = %s", got)
	}
}

func TestProxyErrorKept(t *testing.T) {
	_, err := targetFor([]string{"VAULT_ADDR=https://v", "VAULT_PROXY_ADDR=http://[::1"})
	if err == nil || !strings.Contains(err.Error(), "missing ']'") {
		t.Errorf("err = %v", err)
	}
}

func TestBadAddressReported(t *testing.T) {
	a, out, _ := newTestApp(t)
	writeContexts(t, a, map[string]string{
		"noscheme": "vault.example.com:8200",
		"ok":       serve(t, vaultHandler(200, activeBody)),
	})
	err := a.run([]string{"check"})
	if err == nil || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out.String(), "config: VAULT_ADDR") {
		t.Errorf("output:\n%s", out)
	}

	cfg, err := a.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	m, err := newModel(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 20})
	if view := m.View(); !strings.Contains(view, "config error") {
		t.Errorf("UI:\n%s", view)
	}
	a.environ = withEnv(a.environ, "VCTX_CHECK_TIMEOUT=2s")
	if err := a.run([]string{"noscheme", "status"}); err == nil || strings.Contains(err.Error(), "VPN") {
		t.Errorf("exec with bad address: %v", err)
	}
}

func TestBadProxyReported(t *testing.T) {
	a, out, _ := newTestApp(t)
	cfg := "contexts:\n  x:\n    VAULT_ADDR: https://v\n    VAULT_PROXY_ADDR: http://[::1\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"check"}); err == nil || !strings.Contains(out.String(), "proxy settings") {
		t.Errorf("err = %v, output:\n%s", err, out)
	}
}

func TestUnhealthyNodesAreVault(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   string
		usable bool
	}{
		{474, `{"initialized":true,"sealed":false,"standby":true,"version":"1.20.4"}`, "1.20.4 standby", true},
		{530, `{"initialized":true,"sealed":false,"standby":true,"removed_from_cluster":true,"version":"1.20.4"}`, "1.20.4 removed from cluster", false},
	} {
		addr := serve(t, vaultHandler(tc.status, tc.body))
		r := probeEnv(t, []string{"VAULT_ADDR=" + addr})
		if r.err != nil || r.health.String() != tc.want || r.health.usable() != tc.usable {
			t.Errorf("HTTP %d: err %v, health %+v", tc.status, r.err, r.health)
		}
		a, _, call := newTestApp(t, "VCTX_CHECK_TIMEOUT=2s")
		writeContexts(t, a, map[string]string{"x": addr})
		if err := a.run([]string{"x", "status"}); err != nil || call.argv0 == "" {
			t.Errorf("HTTP %d: vault not started: %v", tc.status, err)
		}
	}
}

func TestInlineCACert(t *testing.T) {
	srv := httptest.NewUnstartedServer(vaultHandler(200, activeBody))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	r := probeEnv(t, []string{"VAULT_ADDR=" + srv.URL, "VAULT_CACERT_BYTES=" + string(pemBytes)})
	if r.err != nil {
		t.Errorf("VAULT_CACERT_BYTES: %v", r.err)
	}
}

func TestReachabilityErrorsClassified(t *testing.T) {
	plain := strings.Replace(serve(t, vaultHandler(200, activeBody)), "http://", "https://", 1)
	a, _, _ := newTestApp(t, "VCTX_CHECK_TIMEOUT=2s")
	writeContexts(t, a, map[string]string{"x": plain})
	if err := a.run([]string{"x", "status"}); err == nil || !strings.Contains(err.Error(), "does not speak TLS") {
		t.Errorf("err = %v", err)
	}

	a, _, _ = newTestApp(t, "VCTX_CHECK_TIMEOUT=2s")
	writeContexts(t, a, map[string]string{"x": "unix://" + filepath.Join(t.TempDir(), "agent.sock")})
	if err := a.run([]string{"x", "status"}); err == nil || !strings.Contains(err.Error(), "vault agent") {
		t.Errorf("agent socket: %v", err)
	}
}

func TestUnixSocketPaths(t *testing.T) {
	for raw, want := range map[string]string{
		"unix:///run/vault.sock": "/run/vault.sock",
		"unix://v.sock":          "v.sock",
	} {
		got, err := targetFor([]string{"VAULT_ADDR=" + raw})
		if err != nil || got.unix != want {
			t.Errorf("%s: unix %q, err %v", raw, got.unix, err)
		}
	}
	if _, err := targetFor([]string{"VAULT_ADDR=unix://"}); err == nil {
		t.Error("empty socket path accepted")
	}
}

func TestProxyRefusal(t *testing.T) {
	proxy := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	r := probeEnv(t, []string{"VAULT_ADDR=https://vault.example.com", "VAULT_PROXY_ADDR=" + proxy})
	short, long := classify(r.err)
	if short != "blocked by proxy" || !networkProblem(r.err) || strings.Contains(long, "Get ") {
		t.Errorf("short %q, long %q, network %v", short, long, networkProblem(r.err))
	}
}

func TestProxyCredentialsNotShown(t *testing.T) {
	for _, env := range [][]string{
		{"VAULT_ADDR=https://v", "VAULT_PROXY_ADDR=http://user:s3cret@[::1"},
		{"VAULT_ADDR=https://v", "HTTPS_PROXY=http://user:s3cret@[::1"},
		{"VAULT_ADDR=https://user:s3cret@[::1"},
	} {
		var shown string
		if tg, err := targetFor(env); err != nil {
			_, shown = classify(err)
		} else {
			shown = tg.String() + " " + tg.display()
		}
		if strings.Contains(shown, "s3cret") {
			t.Errorf("%q: password in %q", env, shown)
		}
	}
}

func TestPlainHTTPToTLSServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(vaultHandler(200, activeBody))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	r := probeEnv(t, []string{"VAULT_ADDR=" + strings.Replace(srv.URL, "https://", "http://", 1)})
	short, long := classify(r.err)
	if short != "config error" || !strings.Contains(long, "use https://") || networkProblem(r.err) {
		t.Errorf("short %q, long %q", short, long)
	}
}

// connectProxy tunnels CONNECT requests to whatever host they name.
func connectProxy(t *testing.T) string {
	t.Helper()
	return serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestNotTLSThroughProxy(t *testing.T) {
	plain := strings.Replace(serve(t, vaultHandler(200, activeBody)), "http://", "https://", 1)
	r := probeEnv(t, []string{"VAULT_ADDR=" + plain, "VAULT_PROXY_ADDR=" + connectProxy(t)})
	if short, long := classify(r.err); short != "not tls" {
		t.Errorf("short %q, long %q", short, long)
	}
}

func TestConnectionClosed(t *testing.T) {
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
			conn.Close()
		}
	}()
	r := probeEnv(t, []string{"VAULT_ADDR=http://" + ln.Addr().String()})
	if short, long := classify(r.err); short != "unreachable" || !strings.Contains(long, "connection closed") || !networkProblem(r.err) {
		t.Errorf("short %q, long %q", short, long)
	}
}

func TestAgentAddrNamedInErrors(t *testing.T) {
	_, err := targetFor([]string{"VAULT_AGENT_ADDR=ftp://agent"})
	if err == nil || !strings.Contains(err.Error(), "VAULT_AGENT_ADDR") {
		t.Errorf("err = %v", err)
	}
}

func TestUnparsableAddressRedacted(t *testing.T) {
	a, out, _ := newTestApp(t)
	writeContexts(t, a, map[string]string{"x": "https://user:s3cret@[::1"})
	for _, args := range [][]string{{"check"}, {"ls"}} {
		out.Reset()
		a.run(args)
		if strings.Contains(out.String(), "s3cret") {
			t.Errorf("%v shows the password:\n%s", args, out)
		}
	}
}
