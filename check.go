package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
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
		return target{}, &configError{fmt.Errorf("parse VAULT_ADDR: %w", err)}
	}
	switch u.Scheme {
	case "unix":
		return target{addr: &url.URL{Scheme: "http", Host: "localhost"}, unix: u.Path}, nil
	case "http", "https":
	default:
		return target{}, &configError{fmt.Errorf("VAULT_ADDR %q: want http://, https:// or unix://", raw)}
	}

	t := target{addr: u}
	if p := get("VAULT_PROXY_ADDR", "VAULT_HTTP_PROXY"); p != "" {
		t.proxy, err = url.Parse(p)
	} else {
		cfg := httpproxy.Config{
			HTTPProxy:  get("HTTP_PROXY", "http_proxy"),
			HTTPSProxy: get("HTTPS_PROXY", "https_proxy"),
			NoProxy:    get("NO_PROXY", "no_proxy"),
		}
		t.proxy, err = cfg.ProxyFunc()(u)
	}
	if err != nil {
		return target{}, &configError{fmt.Errorf("proxy settings for %s: %w", u.Host, err)}
	}
	if t.proxy != nil && t.proxy.Host == "" {
		return target{}, &configError{fmt.Errorf("proxy settings for %s: no host in %q", u.Host, t.proxy.Redacted())}
	}
	return t, nil
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

// probe calls sys/health the way vault would for env. Unauthenticated, read-only.
func probe(ctx context.Context, env []string, timeout time.Duration) probeResult {
	t, err := targetFor(env)
	if err != nil {
		return probeResult{err: err}
	}
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
		return probeResult{err: err}
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
	var nv *notVaultError
	var dnsErr *net.DNSError
	var recErr tls.RecordHeaderError
	var netErr net.Error
	switch {
	case errors.As(err, &cfgErr):
		return "config error", "config: " + sanitize(cfgErr.Error(), 300)
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
	var opErr *net.OpError
	var dnsErr *net.DNSError
	var netErr net.Error
	return errors.As(err, &nv) || errors.As(err, &opErr) || errors.As(err, &dnsErr) ||
		errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

// networkHint suggests what to check when the path to a target is broken.
func networkHint(unix bool) string {
	if unix {
		return "is vault agent running?"
	}
	return "is the VPN/tunnel up?"
}

// checkTimeout reads VCTX_CHECK_TIMEOUT; zero disables the check.
func (a *app) checkTimeout() (time.Duration, error) {
	v := a.getenv("VCTX_CHECK_TIMEOUT")
	if v == "" {
		return defaultCheckTimeout, nil
	}
	if v == "0" || v == "off" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid VCTX_CHECK_TIMEOUT %q, want a duration like 3s or 0 to disable", v)
	}
	return d, nil
}

// ensureReachable fails fast when the Vault API of context name cannot be reached with env.
// TLS problems and an unusable node are left for vault itself to report.
func (a *app) ensureReachable(name string, env []string) error {
	timeout, err := a.checkTimeout()
	if err != nil || timeout == 0 {
		return err
	}
	t, err := targetFor(env)
	if err != nil {
		_, long := classify(err)
		return fmt.Errorf("context %s: %s", name, long)
	}
	r := probe(context.Background(), env, timeout)
	if r.err == nil || isTLSError(r.err) {
		return nil
	}
	_, long := classify(r.err)
	if !networkProblem(r.err) {
		return fmt.Errorf("context %s: %s", name, long)
	}
	return fmt.Errorf("context %s: %s %s\n%s set VCTX_CHECK_TIMEOUT=0 to skip this check",
		name, t, long, networkHint(t.unix != ""))
}

// contextStatus is the probe outcome of one context.
type contextStatus struct {
	name    string
	target  string
	display string
	unix    bool
	probeResult
}

type level int

const (
	levelOK level = iota + 1
	levelWarn
	levelFail
)

func (s contextStatus) summary() (string, level) {
	switch {
	case s.err == nil && s.health == nil:
		return "checking", levelWarn
	case s.err != nil:
		_, long := classify(s.err)
		return long, levelFail
	case !s.health.usable():
		return s.health.String(), levelWarn
	}
	return "ok " + s.health.String(), levelOK
}

// shortSummary is summary with a compact label for errors.
func (s contextStatus) shortSummary() (string, level) {
	if s.err != nil {
		short, _ := classify(s.err)
		return short, levelFail
	}
	return s.summary()
}

func (s contextStatus) latencyText() string {
	if s.err != nil {
		return ""
	}
	return fmt.Sprintf("%dms", max(s.latency.Milliseconds(), 1))
}

// prepare resolves what probing context name needs. An address vctx cannot
// use ends up in the status, so one bad context does not hide the others.
func (a *app) prepare(cfg *config, name string) (contextStatus, []string, error) {
	vars, err := a.contextVars(cfg, name)
	if err != nil {
		return contextStatus{}, nil, err
	}
	env := applyEnv(a.environ, vars)
	s := contextStatus{name: name}
	t, err := targetFor(env)
	if err != nil {
		s.display = sanitize(vaultAddr(vars), 60)
		s.target = s.display
		s.err = err
		return s, env, nil
	}
	s.target, s.display, s.unix = t.String(), t.display(), t.unix != ""
	return s, env, nil
}

// probeAll probes, concurrently, every context whose address could be resolved.
func probeAll(statuses []contextStatus, envs [][]string, timeout time.Duration) {
	var wg sync.WaitGroup
	for i := range statuses {
		if statuses[i].err != nil {
			continue
		}
		wg.Go(func() { statuses[i].probeResult = probe(context.Background(), envs[i], timeout) })
	}
	wg.Wait()
}

// check probes the given contexts, or all of them, and prints a status table.
func (a *app) check(args []string) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	names := args
	if len(names) == 0 {
		names = slices.Sorted(maps.Keys(cfg.Contexts))
	}
	timeout, err := a.checkTimeout()
	if err != nil {
		return err
	}
	if timeout == 0 {
		timeout = defaultCheckTimeout
	}
	statuses := make([]contextStatus, len(names))
	envs := make([][]string, len(names))
	for i, name := range names {
		if statuses[i], envs[i], err = a.prepare(cfg, name); err != nil {
			return err
		}
	}
	a.withSpinner(fmt.Sprintf("checking %d instances", len(names)), func() { probeAll(statuses, envs, timeout) })

	if a.stdoutTTY {
		current, _ := a.contextName("")
		fmt.Fprintln(a.stdout, a.renderStatusTable(statuses, current))
	} else {
		tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
		for _, s := range statuses {
			text, lvl := s.summary()
			if lvl == levelOK {
				text += " " + s.latencyText()
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", s.name, s.target, text)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	failed := 0
	for _, s := range statuses {
		if _, lvl := s.summary(); lvl != levelOK {
			failed++
		}
	}
	switch {
	case failed == 0:
		return nil
	case a.stdoutTTY:
		return errSilent
	}
	return fmt.Errorf("%d of %d contexts not usable", failed, len(names))
}
