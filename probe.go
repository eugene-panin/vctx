package main

import (
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
	"time"
	"unicode"

	"golang.org/x/net/http/httpproxy"
)

const defaultCheckTimeout = 3 * time.Second

// configError is a context setting vctx cannot use, as opposed to a network failure.
type configError struct{ err error }

func (e *configError) Error() string { return e.err.Error() }
func (e *configError) Unwrap() error { return e.err }

// target is where vault will send requests for a given environment.
type target struct {
	addr  *url.URL
	proxy *url.URL
	unix  string
}

func targetFor(env []string) (target, error) {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v := lookupEnv(env, k); v != "" {
				return v
			}
		}
		return ""
	}

	raw := get("VAULT_AGENT_ADDR", "VAULT_ADDR")
	if raw == "" {
		raw = defaultVaultAddr
	}
	u, err := url.Parse(raw)
	if err != nil {
		return target{}, &configError{fmt.Errorf("parse VAULT_ADDR: %w", parseReason(err))}
	}
	switch u.Scheme {
	case "unix":
		// Like Vault, take everything after the scheme: url.Parse puts a relative path in Host.
		path := strings.TrimPrefix(raw, "unix://")
		if path == "" || path == raw {
			return target{}, &configError{errors.New("VAULT_ADDR: unix:// needs a socket path")}
		}
		return target{addr: &url.URL{Scheme: "http", Host: "localhost"}, unix: path}, nil
	case "http", "https":
	default:
		return target{}, &configError{fmt.Errorf("VAULT_ADDR %q: want http://, https:// or unix://", raw)}
	}

	t := target{addr: u}
	if p := get("VAULT_PROXY_ADDR", "VAULT_HTTP_PROXY"); p != "" {
		if t.proxy, err = url.Parse(p); err != nil {
			return target{}, &configError{fmt.Errorf("proxy settings for %s: VAULT_PROXY_ADDR: %w", u.Host, parseReason(err))}
		}
	} else {
		cfg := httpproxy.Config{
			HTTPProxy:  get("HTTP_PROXY", "http_proxy"),
			HTTPSProxy: get("HTTPS_PROXY", "https_proxy"),
			NoProxy:    get("NO_PROXY", "no_proxy"),
		}
		// The error quotes the proxy URL, credentials included, so it is not passed on.
		if t.proxy, err = cfg.ProxyFunc()(u); err != nil {
			return target{}, &configError{fmt.Errorf("proxy settings for %s: invalid HTTP(S)_PROXY", u.Host)}
		}
	}
	if t.proxy != nil && t.proxy.Host == "" {
		return target{}, &configError{fmt.Errorf("proxy settings for %s: no host in %q", u.Host, t.proxy.Redacted())}
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

// display is the address as written in VAULT_ADDR, for humans.
func (t target) display() string {
	switch {
	case t.unix != "":
		return t.unix
	case t.proxy != nil:
		return t.addr.Host + " via " + t.proxy.Host
	}
	return t.addr.Host
}

func (t target) String() string {
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
		ServerName: lookupEnv(env, "VAULT_TLS_SERVER_NAME"),
	}
	if skip, _ := strconv.ParseBool(lookupEnv(env, "VAULT_SKIP_VERIFY")); skip {
		cfg.InsecureSkipVerify = true // #nosec G402 -- explicitly requested by the context
	}

	var pems [][]byte
	switch file, inline, dir := lookupEnv(env, "VAULT_CACERT"), lookupEnv(env, "VAULT_CACERT_BYTES"), lookupEnv(env, "VAULT_CAPATH"); {
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

	if cert, key := lookupEnv(env, "VAULT_CLIENT_CERT"), lookupEnv(env, "VAULT_CLIENT_KEY"); cert != "" && key != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

type health struct {
	Initialized        bool
	Sealed             bool
	Standby            bool
	PerformanceStandby bool
	Removed            bool
	Version            string
}

// decodeHealth parses a sys/health body; ok is false when it is not one.
func decodeHealth(r io.Reader) (h health, ok bool) {
	var wire struct {
		Initialized        *bool  `json:"initialized"`
		Sealed             bool   `json:"sealed"`
		Standby            bool   `json:"standby"`
		PerformanceStandby bool   `json:"performance_standby"`
		Removed            bool   `json:"removed_from_cluster"`
		Version            string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(r, 64<<10)).Decode(&wire); err != nil || wire.Initialized == nil {
		return health{}, false
	}
	return health{
		Initialized:        *wire.Initialized,
		Sealed:             wire.Sealed,
		Standby:            wire.Standby,
		PerformanceStandby: wire.PerformanceStandby,
		Removed:            wire.Removed,
		Version:            sanitize(wire.Version, 40),
	}, true
}

// usable reports whether vault commands can work against this node right now.
func (h health) usable() bool {
	return h.Initialized && !h.Sealed && !h.Removed
}

func (h health) String() string {
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

// notVaultError means something answered at VAULT_ADDR, but not the Vault API:
// typically an ingress or firewall rejecting the client's IP, or redirecting to a login page.
type notVaultError struct {
	status      int
	contentType string
	location    string
}

// proxyError is a proxy refusing to tunnel to Vault (a CONNECT answered with 403 or 407).
type proxyError struct {
	proxy string
	err   error
}

func (e *proxyError) Error() string { return "proxy " + e.proxy + " refused: " + e.err.Error() }
func (e *proxyError) Unwrap() error { return e.err }

func (e *notVaultError) Error() string {
	if e.location != "" {
		return fmt.Sprintf("HTTP %d redirect to %s, not the Vault API", e.status, e.location)
	}
	return fmt.Sprintf("HTTP %d (%s), not the Vault API", e.status, e.contentType)
}

// sanitize makes text from a server or certificate safe to print: control
// characters would let it drive the terminal (retitle, clear, write the clipboard).
func sanitize(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if !unicode.IsPrint(r) {
			continue
		}
		if n == limit {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

type probeResult struct {
	health  *health
	latency time.Duration
	err     error
}

// probe calls sys/health on t the way vault would with env. Unauthenticated, read-only.
func probe(ctx context.Context, t target, env []string, timeout time.Duration) probeResult {
	tlsCfg, err := tlsConfig(env)
	if err != nil {
		return probeResult{err: &configError{err}}
	}
	tr := &http.Transport{
		Proxy:             func(*http.Request) (*url.URL, error) { return t.proxy, nil },
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
		return probeResult{err: err}
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return probeResult{err: proxyRefusal(t, err)}
	}
	defer resp.Body.Close()
	latency := time.Since(start)

	// sys/health signals node state through many status codes (429 standby,
	// 503 sealed, 474 HA unhealthy, 530 removed, ...); the body tells Vault apart.
	if h, ok := decodeHealth(resp.Body); ok {
		return probeResult{health: &h, latency: latency}
	}
	notVault := &notVaultError{status: resp.StatusCode, contentType: sanitize(resp.Header.Get("Content-Type"), 40)}
	if notVault.contentType == "" {
		notVault.contentType = "no content type"
	}
	if loc, err := resp.Location(); err == nil {
		notVault.location = sanitize(loc.Host, 60)
	}
	return probeResult{err: notVault}
}

// proxyRefusal recognizes a failed CONNECT: net/http reports it only as the
// proxy's status text ("Forbidden"), with no type of its own.
func proxyRefusal(t target, err error) error {
	var urlErr *url.Error
	var opErr *net.OpError
	var netErr net.Error
	if t.proxy == nil || !errors.As(err, &urlErr) || errors.As(err, &opErr) ||
		(errors.As(err, &netErr) && netErr.Timeout()) || isTLSError(err) {
		return err
	}
	return &proxyError{proxy: t.proxy.Host, err: urlErr.Err}
}

// isTLSError reports a failed TLS handshake: a certificate the client rejects,
// or an alert from the server (client certificate required, no common version).
func isTLSError(err error) bool {
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

// classify describes err twice: a compact label for tables and a full explanation.
// Error text can carry server or certificate data, so it is sanitized.
func classify(err error) (short, long string) {
	var cfgErr *configError
	var pxErr *proxyError
	var nv *notVaultError
	var dnsErr *net.DNSError
	var recErr tls.RecordHeaderError
	var netErr net.Error
	switch {
	case errors.As(err, &cfgErr):
		return "config error", "config: " + sanitize(cfgErr.Error(), 300)
	case errors.As(err, &pxErr):
		return "blocked by proxy", "blocked: " + sanitize(pxErr.Error(), 300)
	case errors.As(err, &nv):
		return fmt.Sprintf("blocked (HTTP %d)", nv.status), "blocked: " + nv.Error()
	case isTLSError(err):
		var verr *tls.CertificateVerificationError
		if errors.As(err, &verr) {
			err = verr.Err
		}
		var opErr *net.OpError
		if errors.As(err, &opErr) && isTLSAlert(err) {
			err = opErr.Err
		}
		return "tls error", "tls: " + sanitize(err.Error(), 300)
	// net/http reports this case only as text.
	case errors.As(err, &recErr), strings.Contains(err.Error(), "server gave HTTP response to HTTPS client"):
		return "not tls", "tls: server does not speak TLS (http:// instead of https://?)"
	case errors.As(err, &dnsErr):
		return "no dns", "unreachable: cannot resolve " + sanitize(dnsErr.Name, 100)
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout", "unreachable: timed out"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return "unreachable", "unreachable: " + sanitize(opErr.Err.Error(), 300)
	}
	return "error", sanitize(err.Error(), 300)
}

// networkProblem reports whether err comes from the network path to Vault
// rather than from the local configuration or a TLS handshake.
func networkProblem(err error) bool {
	var cfgErr *configError
	if isTLSError(err) || errors.As(err, &cfgErr) {
		return false
	}
	var nv *notVaultError
	var pxErr *proxyError
	var opErr *net.OpError
	var dnsErr *net.DNSError
	var netErr net.Error
	return errors.As(err, &nv) || errors.As(err, &pxErr) || errors.As(err, &opErr) || errors.As(err, &dnsErr) ||
		errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

// networkHint suggests what to check when the path to a target is broken.
func networkHint(unix bool) string {
	if unix {
		return "is vault agent running?"
	}
	return "is the VPN/tunnel up?"
}
