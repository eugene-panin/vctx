// Package probe checks whether a Vault instance can be reached the way the
// Vault CLI would reach it, with an unauthenticated GET /v1/sys/health, and
// explains failures.
package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/environ"
	"github.com/eugene-panin/vctx/internal/termsafe"
	"golang.org/x/net/http/httpproxy"
)

// DefaultTimeout bounds a probe unless VCTX_CHECK_TIMEOUT says otherwise.
const DefaultTimeout = 3 * time.Second

// ConfigError is a context setting vctx cannot use, as opposed to a network failure.
type ConfigError struct{ err error }

func (e *ConfigError) Error() string { return e.err.Error() }
func (e *ConfigError) Unwrap() error { return e.err }

// Target is where vault will send requests for a given environment.
type Target struct {
	addr  *url.URL
	proxy *url.URL
	unix  string
}

// TargetFor resolves where vault sends requests with env.
func TargetFor(env []string) (Target, error) {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v := environ.Value(env, k); v != "" {
				return v
			}
		}
		return ""
	}

	raw, from := config.AddrFrom(func(k string) string { return environ.Value(env, k) })
	if raw == "" {
		raw, from = config.DefaultAddr, "VAULT_ADDR"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, &ConfigError{fmt.Errorf("parse %s: %w", from, parseReason(err))}
	}
	switch u.Scheme {
	case "unix":
		// Like Vault, take everything after the scheme: url.Parse puts a relative path in Host.
		path := strings.TrimPrefix(raw, "unix://")
		if path == "" || path == raw {
			return Target{}, &ConfigError{fmt.Errorf("%s: unix:// needs a socket path", from)}
		}
		return Target{addr: &url.URL{Scheme: "http", Host: "localhost"}, unix: path}, nil
	case "http", "https":
	default:
		return Target{}, &ConfigError{fmt.Errorf("%s %q: want http://, https:// or unix://", from, config.RedactAddr(raw))}
	}

	t := Target{addr: u}
	if p := get("VAULT_PROXY_ADDR", "VAULT_HTTP_PROXY"); p != "" {
		if t.proxy, err = url.Parse(p); err != nil {
			return Target{}, &ConfigError{fmt.Errorf("proxy settings for %s: VAULT_PROXY_ADDR: %w", u.Host, parseReason(err))}
		}
	} else {
		cfg := httpproxy.Config{
			HTTPProxy:  get("HTTP_PROXY", "http_proxy"),
			HTTPSProxy: get("HTTPS_PROXY", "https_proxy"),
			NoProxy:    get("NO_PROXY", "no_proxy"),
		}
		// The error quotes the proxy URL, credentials included, so it is not passed on.
		if t.proxy, err = cfg.ProxyFunc()(u); err != nil {
			return Target{}, &ConfigError{fmt.Errorf("proxy settings for %s: invalid HTTP(S)_PROXY", u.Host)}
		}
	}
	if t.proxy != nil && t.proxy.Host == "" {
		return Target{}, &ConfigError{fmt.Errorf("proxy settings for %s: no host in %q", u.Host, t.proxy.Redacted())}
	}
	return t, nil
}

// parseReason drops the input url.Parse quotes in its error, which may hold credentials.
func parseReason(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

// Display is the host vault talks to, and the proxy if any, for humans.
func (t Target) Display() string {
	switch {
	case t.unix != "":
		return t.unix
	case t.proxy != nil:
		return t.addr.Host + " via " + t.proxy.Host
	}
	return t.addr.Host
}

// IsUnix reports whether t is a unix socket.
func (t Target) IsUnix() bool { return t.unix != "" }

func (t Target) String() string {
	switch {
	case t.unix != "":
		return t.unix
	case t.proxy != nil:
		return hostPort(t.addr) + " via " + hostPort(t.proxy)
	}
	return hostPort(t.addr)
}

func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	port := "80"
	switch u.Scheme {
	case "https":
		port = "443"
	case "socks5", "socks5h":
		port = "1080"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// tlsConfig mirrors the TLS variables the Vault CLI understands, with the same
// precedence for CA certificates: file, then inline PEM, then directory.
func tlsConfig(env []string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: environ.Value(env, "VAULT_TLS_SERVER_NAME"),
	}
	if skip, _ := strconv.ParseBool(environ.Value(env, "VAULT_SKIP_VERIFY")); skip {
		cfg.InsecureSkipVerify = true // #nosec G402 -- explicitly requested by the context
	}

	var pems [][]byte
	switch file, inline, dir := environ.Value(env, "VAULT_CACERT"), environ.Value(env, "VAULT_CACERT_BYTES"), environ.Value(env, "VAULT_CAPATH"); {
	case file != "":
		pem, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
		pems = append(pems, pem)
	case inline != "":
		pems = append(pems, []byte(inline))
	case dir != "":
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("read VAULT_CAPATH: %w", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			pem, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return nil, fmt.Errorf("read CA certificate: %w", err)
			}
			pems = append(pems, pem)
		}
	}
	if len(pems) > 0 {
		cfg.RootCAs = x509.NewCertPool()
		for _, pem := range pems {
			if !cfg.RootCAs.AppendCertsFromPEM(pem) {
				return nil, errors.New("no certificates in the configured CA")
			}
		}
	}

	if cert, key := environ.Value(env, "VAULT_CLIENT_CERT"), environ.Value(env, "VAULT_CLIENT_KEY"); cert != "" && key != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// Health is what sys/health tells about a node.
type Health struct {
	Initialized        bool
	Sealed             bool
	Standby            bool
	PerformanceStandby bool
	Removed            bool
	Version            string
}

// decodeHealth parses a sys/health body; ok is false when it is not one.
func decodeHealth(body []byte) (h Health, ok bool) {
	var wire struct {
		Initialized        *bool  `json:"initialized"`
		Sealed             bool   `json:"sealed"`
		Standby            bool   `json:"standby"`
		PerformanceStandby bool   `json:"performance_standby"`
		Removed            bool   `json:"removed_from_cluster"`
		Version            string `json:"version"`
	}
	if err := json.Unmarshal(body, &wire); err != nil || wire.Initialized == nil {
		return Health{}, false
	}
	return Health{
		Initialized:        *wire.Initialized,
		Sealed:             wire.Sealed,
		Standby:            wire.Standby,
		PerformanceStandby: wire.PerformanceStandby,
		Removed:            wire.Removed,
		Version:            termsafe.String(wire.Version, 40),
	}, true
}

// Usable reports whether vault commands can work against this node right now.
func (h Health) Usable() bool {
	return h.Initialized && !h.Sealed && !h.Removed
}

func (h Health) String() string {
	state := "active"
	switch {
	case !h.Initialized:
		state = "not initialized"
	case h.Sealed:
		state = "sealed"
	case h.Removed:
		state = "removed from cluster"
	case h.PerformanceStandby:
		state = "perf standby"
	case h.Standby:
		state = "standby"
	}
	return h.Version + " " + state
}

// NotVaultError means something answered at VAULT_ADDR, but not the Vault API:
// typically an ingress or firewall rejecting the client's IP, or redirecting to a login page.
type NotVaultError struct {
	Status      int
	ContentType string
	Location    string
}

// ProxyError is a proxy answering CONNECT with anything but 200: refusing the
// tunnel (403, 407) or failing to reach Vault itself (502, 503, 504).
type ProxyError struct {
	proxy  string
	status string // as sent, e.g. "504 Gateway Time-out"
	code   int
}

// upstream reports a proxy that accepted the tunnel but could not reach the server.
func (e *ProxyError) upstream() bool {
	return e.code == http.StatusBadGateway || e.code == http.StatusServiceUnavailable || e.code == http.StatusGatewayTimeout
}

func (e *ProxyError) Error() string {
	if e.upstream() {
		return "proxy " + e.proxy + " cannot reach the server: " + e.status
	}
	return "proxy " + e.proxy + " refused: " + e.status
}

func (e *NotVaultError) Error() string {
	if e.Location != "" {
		return fmt.Sprintf("HTTP %d redirect to %s, not the Vault API", e.Status, e.Location)
	}
	return fmt.Sprintf("HTTP %d (%s), not the Vault API", e.Status, e.ContentType)
}

// Result is the outcome of a probe: Health when Vault answered, Err otherwise.
type Result struct {
	Health  *Health
	Latency time.Duration
	Err     error
}

// Probe calls sys/health on t the way vault would with env. Unauthenticated, read-only.
func Probe(ctx context.Context, t Target, env []string, timeout time.Duration) Result {
	tlsCfg, err := tlsConfig(env)
	if err != nil {
		return Result{Err: &ConfigError{err}}
	}
	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return t.proxy, nil },
		// net/http reports a failed CONNECT only by its status text; keep the code.
		OnProxyConnectResponse: func(_ context.Context, proxy *url.URL, _ *http.Request, resp *http.Response) error {
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			return &ProxyError{proxy: proxy.Host, status: termsafe.String(resp.Status, 60), code: resp.StatusCode}
		},
		TLSClientConfig:   tlsCfg,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
	}
	if t.unix != "" {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", t.unix)
		}
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// A redirect is reported, not followed: Vault never redirects sys/health,
		// and following would present a client certificate to whatever host it names.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.addr.JoinPath("v1/sys/health").String(), nil)
	if err != nil {
		return Result{Err: err}
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{Err: err}
	}
	defer resp.Body.Close()
	latency := time.Since(start)

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return Result{Err: err}
	}
	// sys/health signals node state through many status codes (429 standby,
	// 503 sealed, 474 HA unhealthy, 530 removed, ...); the body tells Vault apart.
	if h, ok := decodeHealth(body); ok {
		return Result{Health: &h, Latency: latency}
	}
	// Go's TLS servers, Vault included, answer plain HTTP with this 400.
	if resp.StatusCode == http.StatusBadRequest && bytes.Contains(body, []byte("HTTP request to an HTTPS server")) {
		return Result{Err: &ConfigError{errors.New("the server speaks TLS: use https:// in the address")}}
	}
	// For an http:// address the proxy forwards the request instead of opening
	// a tunnel, so its own gateway errors arrive as ordinary responses.
	if pe := (&ProxyError{code: resp.StatusCode}); t.proxy != nil && t.addr.Scheme == "http" && pe.upstream() {
		pe.proxy, pe.status = t.proxy.Host, termsafe.String(resp.Status, 60)
		return Result{Err: pe}
	}
	notVault := &NotVaultError{Status: resp.StatusCode, ContentType: termsafe.String(resp.Header.Get("Content-Type"), 40)}
	if notVault.ContentType == "" {
		notVault.ContentType = "no content type"
	}
	if loc, err := resp.Location(); err == nil {
		notVault.Location = termsafe.String(loc.Host, 60)
	}
	return Result{Err: notVault}
}

// notTLS matches a TLS client talking to a plain HTTP server; net/http reports
// it as a tls.RecordHeaderError or, after reading a response, only as text.
func notTLS(err error) bool {
	var recErr tls.RecordHeaderError
	return errors.As(err, &recErr) || strings.Contains(err.Error(), "server gave HTTP response to HTTPS client")
}

// connClosed matches a server that accepted the connection and dropped it,
// such as a Vault cluster port spoken to over HTTP.
func connClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET)
}

// IsTLSError reports a failed TLS handshake: a certificate the client rejects,
// or an alert from the server (client certificate required, no common version).
func IsTLSError(err error) bool {
	var verr *tls.CertificateVerificationError
	var herr x509.HostnameError
	var uerr x509.UnknownAuthorityError
	var cerr x509.CertificateInvalidError
	return errors.As(err, &verr) || errors.As(err, &herr) || errors.As(err, &uerr) || errors.As(err, &cerr) || isTLSAlert(err)
}

// isTLSAlert matches how crypto/tls reports an alert received from the peer;
// the alert type itself is unexported.
func isTLSAlert(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "remote error"
}

// Classify describes err twice: a compact label for tables and a full explanation.
// Error text can carry server or certificate data, so it is sanitized.
func Classify(err error) (short, long string) {
	var cfgErr *ConfigError
	var pxErr *ProxyError
	var nv *NotVaultError
	var dnsErr *net.DNSError
	var netErr net.Error
	switch {
	case errors.As(err, &cfgErr):
		return "config error", "config: " + termsafe.String(cfgErr.Error(), 300)
	case errors.As(err, &pxErr) && pxErr.upstream():
		return "proxy can't reach", "unreachable: " + termsafe.String(pxErr.Error(), 300)
	case errors.As(err, &pxErr):
		return "blocked by proxy", "blocked: " + termsafe.String(pxErr.Error(), 300)
	case errors.As(err, &nv):
		return fmt.Sprintf("blocked (HTTP %d)", nv.Status), "blocked: " + nv.Error()
	case IsTLSError(err):
		var verr *tls.CertificateVerificationError
		if errors.As(err, &verr) {
			err = verr.Err
		}
		var opErr *net.OpError
		if errors.As(err, &opErr) && isTLSAlert(err) {
			err = opErr.Err
		}
		return "tls error", "tls: " + termsafe.String(strings.TrimPrefix(err.Error(), "tls: "), 300)
	// net/http reports this case only as text.
	case notTLS(err):
		return "not tls", "tls: server does not speak TLS (http:// instead of https://?)"
	case connClosed(err):
		return "unreachable", "unreachable: connection closed by the server"
	case errors.As(err, &dnsErr):
		return "no dns", "unreachable: cannot resolve " + termsafe.String(dnsErr.Name, 100)
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout", "unreachable: timed out"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return "unreachable", "unreachable: " + termsafe.String(opErr.Err.Error(), 300)
	}
	return "error", termsafe.String(err.Error(), 300)
}

// NetworkProblem reports whether err comes from the network path to Vault
// rather than from the local configuration or a TLS handshake.
func NetworkProblem(err error) bool {
	var cfgErr *ConfigError
	if IsTLSError(err) || errors.As(err, &cfgErr) {
		return false
	}
	var nv *NotVaultError
	var pxErr *ProxyError
	var opErr *net.OpError
	var dnsErr *net.DNSError
	var netErr net.Error
	if notTLS(err) {
		return false
	}
	return connClosed(err) || errors.As(err, &nv) || errors.As(err, &pxErr) || errors.As(err, &opErr) || errors.As(err, &dnsErr) ||
		errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

// NetworkHint suggests what to check when the path to a target is broken.
func NetworkHint(unix bool) string {
	if unix {
		return "is vault agent running?"
	}
	return "is the VPN/tunnel up?"
}
