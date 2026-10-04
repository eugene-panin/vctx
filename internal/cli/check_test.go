package cli

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eugene-panin/vctx/internal/vaulttest"
)

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
		{"active", func(t *testing.T) string { return vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody)) }, ""},
		{"sealed runs anyway", func(t *testing.T) string { return vaulttest.Serve(t, vaulttest.Handler(503, vaulttest.SealedBody)) }, ""},
		{"ingress 403", func(t *testing.T) string { return vaulttest.Serve(t, vaulttest.Forbidden()) }, "blocked: HTTP 403"},
		{"html 503", func(t *testing.T) string {
			return vaulttest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "maintenance", http.StatusServiceUnavailable)
			}))
		}, "not the Vault API"},
		{"nothing listening", vaulttest.ClosedURL, "unreachable"},
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
	writeContexts(t, a, map[string]string{"x": vaulttest.ClosedURL(t)})
	if err := a.run([]string{"x", "status"}); err != nil || call.argv0 == "" {
		t.Fatalf("err = %v, ran = %v", err, call.argv0 != "")
	}
}

// An untrusted certificate is left for vault to report, so the command still runs.
func TestUntrustedCertLeftToVault(t *testing.T) {
	srv := httptest.NewUnstartedServer(vaulttest.Handler(200, vaulttest.ActiveBody))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	a, _, call := newTestApp(t, "VCTX_CHECK_TIMEOUT=2s")
	writeContexts(t, a, map[string]string{"x": srv.URL})
	if err := a.run([]string{"x", "status"}); err != nil || call.argv0 == "" {
		t.Fatalf("err = %v, ran = %v", err, call.argv0 != "")
	}
}

func TestCheckCommand(t *testing.T) {
	a, out, _ := newTestApp(t)
	writeContexts(t, a, map[string]string{
		"active":  vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody)),
		"blocked": vaulttest.Serve(t, vaulttest.Forbidden()),
		"down":    vaulttest.ClosedURL(t),
		"sealed":  vaulttest.Serve(t, vaulttest.Handler(503, vaulttest.SealedBody)),
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
	cfg := "contexts:\n  x:\n    VAULT_ADDR: " + vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody)) + "\n    VAULT_CACERT: /nonexistent/ca.pem\n"
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

func TestTLSAlertLeftToVault(t *testing.T) {
	srv := httptest.NewUnstartedServer(vaulttest.Handler(200, vaulttest.ActiveBody))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	a, _, call := newTestApp(t, "VCTX_CHECK_TIMEOUT=2s")
	cfg := "contexts:\n  x:\n    VAULT_ADDR: " + srv.URL + "\n    VAULT_SKIP_VERIFY: \"true\"\n"
	if err := os.WriteFile(a.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"x", "status"}); err != nil || call.argv0 == "" {
		t.Fatalf("vault not started: err = %v", err)
	}
}

func TestBadAddressReported(t *testing.T) {
	a, out, _ := newTestApp(t)
	writeContexts(t, a, map[string]string{
		"noscheme": "vault.example.com:8200",
		"ok":       vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody)),
	})
	err := a.run([]string{"check"})
	if err == nil || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out.String(), "config: VAULT_ADDR") {
		t.Errorf("output:\n%s", out)
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

func TestUnhealthyNodesRunVault(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{474, `{"initialized":true,"sealed":false,"standby":true,"version":"1.20.4"}`},
		{530, `{"initialized":true,"sealed":false,"standby":true,"removed_from_cluster":true,"version":"1.20.4"}`},
	} {
		addr := vaulttest.Serve(t, vaulttest.Handler(tc.status, tc.body))
		a, _, call := newTestApp(t, "VCTX_CHECK_TIMEOUT=2s")
		writeContexts(t, a, map[string]string{"x": addr})
		if err := a.run([]string{"x", "status"}); err != nil || call.argv0 == "" {
			t.Errorf("HTTP %d: vault not started: %v", tc.status, err)
		}
	}
}

func TestReachabilityErrorsClassified(t *testing.T) {
	plain := strings.Replace(vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody)), "http://", "https://", 1)
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
