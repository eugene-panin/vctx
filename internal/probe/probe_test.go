package probe

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

	"github.com/eugene-panin/vctx/internal/vaulttest"
)

// probeEnv probes the target env resolves to, as vctx does before running vault.
func probeEnv(t *testing.T, env []string) Result {
	t.Helper()
	tg, err := TargetFor(env)
	if err != nil {
		return Result{Err: err}
	}
	return Probe(t.Context(), tg, env, DefaultTimeout)
}

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
			got, err := TargetFor(tc.env)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestServerTextSanitized(t *testing.T) {
	body := `{"initialized":true,"sealed":false,"version":"1.0\u001b]0;PWNED\u0007\u001b[2J"}`
	r := probeEnv(t, []string{"VAULT_ADDR=" + vaulttest.Serve(t, vaulttest.Handler(200, body))})
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if strings.ContainsAny(r.Health.Version, "\x1b\x07") || r.Health.Version != "1.0]0;PWNED[2J" {
		t.Errorf("version = %q", r.Health.Version)
	}
}

func TestRedirectReported(t *testing.T) {
	addr := vaulttest.Serve(t, http.RedirectHandler("https://sso.example.com/login", http.StatusFound))
	r := probeEnv(t, []string{"VAULT_ADDR=" + addr})
	short, long := Classify(r.Err)
	if short != "blocked (HTTP 302)" || !strings.Contains(long, "redirect to sso.example.com") {
		t.Errorf("short %q, long %q", short, long)
	}
}

func TestAgentAddrWins(t *testing.T) {
	got, err := TargetFor([]string{"VAULT_ADDR=https://vault:8200", "VAULT_AGENT_ADDR=http://127.0.0.1:8100"})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "127.0.0.1:8100" {
		t.Errorf("target = %s", got)
	}
}

func TestProxyErrorKept(t *testing.T) {
	_, err := TargetFor([]string{"VAULT_ADDR=https://v", "VAULT_PROXY_ADDR=http://[::1"})
	if err == nil || !strings.Contains(err.Error(), "missing ']'") {
		t.Errorf("err = %v", err)
	}
}

func TestInlineCACert(t *testing.T) {
	srv := httptest.NewUnstartedServer(vaulttest.Handler(200, vaulttest.ActiveBody))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	r := probeEnv(t, []string{"VAULT_ADDR=" + srv.URL, "VAULT_CACERT_BYTES=" + string(pemBytes)})
	if r.Err != nil {
		t.Errorf("VAULT_CACERT_BYTES: %v", r.Err)
	}
}

func TestUnixSocketPaths(t *testing.T) {
	for raw, want := range map[string]string{
		"unix:///run/vault.sock": "/run/vault.sock",
		"unix://v.sock":          "v.sock",
	} {
		got, err := TargetFor([]string{"VAULT_ADDR=" + raw})
		if err != nil || got.unix != want {
			t.Errorf("%s: unix %q, err %v", raw, got.unix, err)
		}
	}
	if _, err := TargetFor([]string{"VAULT_ADDR=unix://"}); err == nil {
		t.Error("empty socket path accepted")
	}
}

func TestProxyRefusal(t *testing.T) {
	proxy := vaulttest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	r := probeEnv(t, []string{"VAULT_ADDR=https://vault.example.com", "VAULT_PROXY_ADDR=" + proxy})
	short, long := Classify(r.Err)
	if short != "blocked by proxy" || !NetworkProblem(r.Err) || strings.Contains(long, "Get ") {
		t.Errorf("short %q, long %q, network %v", short, long, NetworkProblem(r.Err))
	}
}

func TestProxyCredentialsNotShown(t *testing.T) {
	for _, env := range [][]string{
		{"VAULT_ADDR=https://v", "VAULT_PROXY_ADDR=http://user:s3cret@[::1"},
		{"VAULT_ADDR=https://v", "HTTPS_PROXY=http://user:s3cret@[::1"},
		{"VAULT_ADDR=https://user:s3cret@[::1"},
	} {
		var shown string
		if tg, err := TargetFor(env); err != nil {
			_, shown = Classify(err)
		} else {
			shown = tg.String() + " " + tg.Display()
		}
		if strings.Contains(shown, "s3cret") {
			t.Errorf("%q: password in %q", env, shown)
		}
	}
}

func TestPlainHTTPToTLSServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(vaulttest.Handler(200, vaulttest.ActiveBody))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	r := probeEnv(t, []string{"VAULT_ADDR=" + strings.Replace(srv.URL, "https://", "http://", 1)})
	short, long := Classify(r.Err)
	if short != "config error" || !strings.Contains(long, "use https://") || NetworkProblem(r.Err) {
		t.Errorf("short %q, long %q", short, long)
	}
}

func TestNotTLSThroughProxy(t *testing.T) {
	plain := strings.Replace(vaulttest.Serve(t, vaulttest.Handler(200, vaulttest.ActiveBody)), "http://", "https://", 1)
	r := probeEnv(t, []string{"VAULT_ADDR=" + plain, "VAULT_PROXY_ADDR=" + vaulttest.ConnectProxy(t)})
	if short, long := Classify(r.Err); short != "not tls" {
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
	if short, long := Classify(r.Err); short != "unreachable" || !strings.Contains(long, "connection closed") || !NetworkProblem(r.Err) {
		t.Errorf("short %q, long %q", short, long)
	}
}

func TestAgentAddrNamedInErrors(t *testing.T) {
	_, err := TargetFor([]string{"VAULT_AGENT_ADDR=ftp://agent"})
	if err == nil || !strings.Contains(err.Error(), "VAULT_AGENT_ADDR") {
		t.Errorf("err = %v", err)
	}
}

func TestProxyCannotReachUpstream(t *testing.T) {
	proxy := vaulttest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream down", http.StatusBadGateway)
	}))
	r := probeEnv(t, []string{"VAULT_ADDR=https://vault.example.com", "VAULT_PROXY_ADDR=" + proxy})
	if short, long := Classify(r.Err); short != "proxy can't reach" || !strings.Contains(long, "cannot reach") || !NetworkProblem(r.Err) {
		t.Errorf("short %q, long %q", short, long)
	}
}

func TestProxyStatusCodes(t *testing.T) {
	for line, want := range map[string]string{
		"504 Gateway Time-out":              "proxy can't reach",
		"502 Proxy Error":                   "proxy can't reach",
		"503 ":                              "proxy can't reach",
		"407 Proxy Authentication Required": "blocked by proxy",
	} {
		r := probeEnv(t, []string{"VAULT_ADDR=https://vault.example.com", "VAULT_PROXY_ADDR=" + vaulttest.RawProxy(t, line)})
		if short, long := Classify(r.Err); short != want {
			t.Errorf("%q: short %q, long %q", line, short, long)
		}
	}
}

func TestProxyGatewayErrorForPlainHTTP(t *testing.T) {
	r := probeEnv(t, []string{"VAULT_ADDR=http://vault.example.com", "VAULT_PROXY_ADDR=" + vaulttest.RawProxy(t, "504 Gateway Time-out")})
	if short, long := Classify(r.Err); short != "proxy can't reach" || !NetworkProblem(r.Err) {
		t.Errorf("short %q, long %q", short, long)
	}
}

func TestTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(vaulttest.Handler(200, vaulttest.ActiveBody))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{"VAULT_ADDR=" + srv.URL}
	if r := probeEnv(t, env); !IsTLSError(r.Err) {
		t.Errorf("without CA: err = %v, want a TLS verification error", r.Err)
	}
	if r := probeEnv(t, append(env, "VAULT_CACERT="+caFile)); r.Err != nil {
		t.Errorf("with VAULT_CACERT: %v", r.Err)
	}
	if r := probeEnv(t, append(env, "VAULT_SKIP_VERIFY=true")); r.Err != nil {
		t.Errorf("with VAULT_SKIP_VERIFY: %v", r.Err)
	}
}

func TestTLSAlertIsNoNetworkProblem(t *testing.T) {
	srv := httptest.NewUnstartedServer(vaulttest.Handler(200, vaulttest.ActiveBody))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	r := probeEnv(t, []string{"VAULT_ADDR=" + srv.URL, "VAULT_SKIP_VERIFY=true"})
	if !IsTLSError(r.Err) || NetworkProblem(r.Err) {
		t.Fatalf("err = %v: tls %v, network %v", r.Err, IsTLSError(r.Err), NetworkProblem(r.Err))
	}
	if short, long := Classify(r.Err); short != "tls error" || strings.Contains(long, "unreachable") || strings.Contains(long, "tls: tls:") {
		t.Errorf("short %q, long %q", short, long)
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
		r := probeEnv(t, []string{"VAULT_ADDR=" + vaulttest.Serve(t, vaulttest.Handler(tc.status, tc.body))})
		if r.Err != nil || r.Health.String() != tc.want || r.Health.Usable() != tc.usable {
			t.Errorf("HTTP %d: err %v, health %+v", tc.status, r.Err, r.Health)
		}
	}
}
