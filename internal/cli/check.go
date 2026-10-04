package cli

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/eugene-panin/vctx/internal/probe"
	"github.com/eugene-panin/vctx/internal/style"
	"github.com/eugene-panin/vctx/internal/table"
)

// checkTimeout reads VCTX_CHECK_TIMEOUT; zero disables the check.
func (a *app) checkTimeout() (time.Duration, error) {
	v := a.getenv("VCTX_CHECK_TIMEOUT")
	if v == "" {
		return probe.DefaultTimeout, nil
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
	t, err := probe.TargetFor(env)
	if err != nil {
		_, long := probe.Classify(err)
		return fmt.Errorf("context %s: %s", name, long)
	}
	var r probe.Result
	a.spin(fmt.Sprintf("checking %s at %s", name, t), func() { r = probe.Probe(context.Background(), t, env, timeout) })
	if r.Err == nil || probe.IsTLSError(r.Err) {
		return nil
	}
	_, long := probe.Classify(r.Err)
	if !probe.NetworkProblem(r.Err) {
		return fmt.Errorf("context %s: %s", name, long)
	}
	return fmt.Errorf("context %s: %s %s\n%s set VCTX_CHECK_TIMEOUT=0 to skip this check",
		name, t, long, probe.NetworkHint(t.IsUnix()))
}

// checkEntry is one context in 'vctx check --json'; the field names are an interface.
type checkEntry struct {
	Name      string `json:"name"`
	Endpoint  string `json:"endpoint"`
	Usable    bool   `json:"usable"`
	Status    string `json:"status"`
	Version   string `json:"version"`
	LatencyMS *int64 `json:"latency_ms"`
}

// check probes the given contexts, or all of them, and prints a status table,
// or JSON with asJSON.
func (a *app) check(args []string, asJSON bool) error {
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
		timeout = probe.DefaultTimeout
	}
	ps := make([]probe.Instance, len(names))
	for i, name := range names {
		if ps[i], err = probe.Resolve(cfg, name, a.environ, a.home); err != nil {
			return err
		}
	}
	a.spin(fmt.Sprintf("checking %d instances", len(names)), func() { probe.All(ps, timeout) })
	statuses := make([]probe.Status, len(ps))
	for i := range ps {
		statuses[i] = ps[i].Status
	}

	switch {
	case asJSON:
		entries := make([]checkEntry, len(statuses))
		for i, s := range statuses {
			text, lvl := s.Summary()
			e := checkEntry{Name: s.Name, Endpoint: s.Endpoint, Usable: lvl == probe.OK, Status: text}
			if s.Health != nil {
				e.Version = s.Health.Version
			}
			if s.Err == nil {
				ms := max(s.Latency.Milliseconds(), 1)
				e.LatencyMS = &ms
			}
			entries[i] = e
		}
		if err := writeJSON(a.stdout, entries); err != nil {
			return err
		}
	case a.stdoutTTY:
		current, _ := a.contextName("")
		tokens, tokenErr := a.tokenStatus(cfg, names)
		fmt.Fprintln(a.stdout, table.Render(a.stdout, statuses, current, tokens, tokenErr))
	default:
		tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
		for _, s := range statuses {
			text, lvl := s.Summary()
			if lvl == probe.OK {
				text += " " + s.LatencyText()
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Name, s.Endpoint, text)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	failed := 0
	for _, s := range statuses {
		if _, lvl := s.Summary(); lvl != probe.OK {
			failed++
		}
	}
	switch {
	case failed == 0:
		return nil
	case a.stdoutTTY && !asJSON:
		return errSilent
	}
	return fmt.Errorf("%d of %d contexts not usable", failed, len(names))
}

// spinDelay keeps quick operations from flashing a spinner.
const spinDelay = 300 * time.Millisecond

// spin runs fn, animating a spinner on stderr when it is a terminal and fn
// takes longer than spinDelay.
func (a *app) spin(title string, fn func()) {
	if !a.stderrTTY {
		fn()
		return
	}
	f := a.stderr
	p := style.New(f)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		select {
		case <-done:
			return
		case <-time.After(spinDelay):
		}
		frames := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
		tick := time.NewTicker(80 * time.Millisecond)
		defer tick.Stop()
		for i := 0; ; i++ {
			fmt.Fprintf(f, "\r%s %s", p.Accent.Render(string(frames[i%len(frames)])), p.Dim.Render(title))
			select {
			case <-done:
				fmt.Fprint(f, "\r\x1b[2K")
				return
			case <-tick.C:
			}
		}
	})
	fn()
	close(done)
	wg.Wait()
}
