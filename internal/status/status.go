// Package status describes the contexts vctx knows: what each resolves to,
// and what a probe found.
package status

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/eugene-panin/vctx/internal/config"
	"github.com/eugene-panin/vctx/internal/environ"
	"github.com/eugene-panin/vctx/internal/probe"
	"github.com/eugene-panin/vctx/internal/termsafe"
)

// Status is the probe outcome of one context.
type Status struct {
	Name     string
	Endpoint string // host:port vctx connects to, and the proxy if any
	Display  string
	Unix     bool
	probe.Result
}

// Level grades a status for display.
type Level int

const (
	OK Level = iota + 1
	Warn
	Fail
)

// Summary describes s in full.
func (s Status) Summary() (string, Level) {
	switch {
	case s.Err == nil && s.Health == nil:
		return "checking", Warn
	case s.Err != nil:
		_, long := probe.Classify(s.Err)
		return long, Fail
	case !s.Health.Usable():
		return s.Health.String(), Warn
	}
	return "ok " + s.Health.String(), OK
}

// Short is Summary with a compact label for errors.
func (s Status) Short() (string, Level) {
	if s.Err != nil {
		short, _ := probe.Classify(s.Err)
		return short, Fail
	}
	return s.Summary()
}

// LatencyText is the probe's latency for display, empty after an error.
func (s Status) LatencyText() string {
	if s.Err != nil {
		return ""
	}
	return fmt.Sprintf("%dms", max(s.Latency.Milliseconds(), 1))
}

// Context is a context resolved once: what to probe, and the variables to
// run commands with (after environ.RegisterHelper adds the token helper).
type Context struct {
	Status Status
	Vars   map[string]string // environ.ContextVars: as configured, plus vctx bookkeeping
	Env    []string          // environment for probing
	Target probe.Target
	// The address could not be resolved: Status.Err says why, and there is nothing to probe.
	BadAddr bool
}

// Prepare resolves context name over osEnv. An address vctx cannot use ends
// up in the status, so one bad context does not hide the others.
func Prepare(cfg *config.Config, name string, osEnv []string, home string) (Context, error) {
	vars, err := environ.ContextVars(cfg, name, home)
	if err != nil {
		return Context{}, err
	}
	c := Context{Status: Status{Name: name}, Vars: vars, Env: environ.Apply(osEnv, vars)}
	if c.Target, err = probe.TargetFor(c.Env); err != nil {
		c.Status.Display = termsafe.String(config.RedactAddr(config.VaultAddr(vars)), 60)
		c.Status.Endpoint = c.Status.Display
		c.Status.Err = err
		c.BadAddr = true
		return c, nil
	}
	c.Status.Endpoint, c.Status.Display, c.Status.Unix = c.Target.String(), c.Target.Display(), c.Target.IsUnix()
	return c, nil
}

// Probe checks c's instance.
func (c *Context) Probe(timeout time.Duration) probe.Result {
	return probe.Probe(context.Background(), c.Target, c.Env, timeout)
}

// ProbeAll probes, concurrently, every context whose address could be resolved.
func ProbeAll(cs []Context, timeout time.Duration) {
	var wg sync.WaitGroup
	for i := range cs {
		if !cs[i].BadAddr {
			wg.Go(func() { cs[i].Status.Result = cs[i].Probe(timeout) })
		}
	}
	wg.Wait()
}
