package main

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"text/tabwriter"
	"time"
)

// checkTimeout reads VCTX_CHECK_TIMEOUT; zero disables the check.
func (a *app) checkTimeout() (time.Duration, error) {
	v := a.getenv("VCTX_CHECK_TIMEOUT")
	if v == "" {
		return defaultCheckTimeout, nil
	}
	if v == "0" {
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
	r := probe(context.Background(), t, env, timeout)
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
	name     string
	endpoint string // host:port vctx connects to, and the proxy if any
	display  string
	unix     bool
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

// prepared is a context resolved once: what to probe, and the variables to
// run commands with (after registerHelper adds the token helper).
type prepared struct {
	status contextStatus
	vars   map[string]string // contextVars: as configured, plus vctx bookkeeping
	env    []string          // environment for probing
	target target
	// The address could not be resolved: status.err says why, and there is nothing to probe.
	badAddr bool
}

// prepare resolves a context once for probing and for running commands. An
// address vctx cannot use ends up in the status, so one bad context does not hide the others.
func (a *app) prepare(cfg *config, name string) (prepared, error) {
	vars, err := a.contextVars(cfg, name)
	if err != nil {
		return prepared{}, err
	}
	p := prepared{status: contextStatus{name: name}, vars: vars, env: applyEnv(a.environ, vars)}
	if p.target, err = targetFor(p.env); err != nil {
		p.status.display = sanitize(redactAddr(vaultAddr(vars)), 60)
		p.status.endpoint = p.status.display
		p.status.err = err
		p.badAddr = true
		return p, nil
	}
	p.status.endpoint, p.status.display, p.status.unix = p.target.String(), p.target.display(), p.target.unix != ""
	return p, nil
}

func (p *prepared) probeHealth(timeout time.Duration) probeResult {
	return probe(context.Background(), p.target, p.env, timeout)
}

// probeAll probes, concurrently, every context whose address could be resolved.
func probeAll(ps []prepared, timeout time.Duration) {
	var wg sync.WaitGroup
	for i := range ps {
		if !ps[i].badAddr {
			wg.Go(func() { ps[i].status.probeResult = ps[i].probeHealth(timeout) })
		}
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
	ps := make([]prepared, len(names))
	for i, name := range names {
		if ps[i], err = a.prepare(cfg, name); err != nil {
			return err
		}
	}
	a.withSpinner(fmt.Sprintf("checking %d instances", len(names)), func() { probeAll(ps, timeout) })
	statuses := make([]contextStatus, len(ps))
	for i := range ps {
		statuses[i] = ps[i].status
	}

	if a.stdoutTTY {
		current, _ := a.contextName("")
		fmt.Fprintln(a.stdout, a.renderStatusTable(cfg, statuses, current))
	} else {
		tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
		for _, s := range statuses {
			text, lvl := s.summary()
			if lvl == levelOK {
				text += " " + s.latencyText()
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", s.name, s.endpoint, text)
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
