package transfer

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/pkg/config"
)

// Backoff returns the delay before a given 1-based attempt: exponential on
// BaseDelay, capped at MaxDelay BEFORE jitter is applied, with symmetric jitter
// of +/- (Jitter*delay) selected by frac in [0,1) (frac=0.5 => no offset).
// Because jitter is applied after the cap, once the cap is reached the returned
// value lies in MaxDelay*(1-Jitter) .. MaxDelay*(1+Jitter); this
// jitter-around-the-cap is intentional. frac is injected so tests are
// deterministic; callers pass a real random fraction in production.
func Backoff(p config.RetryPolicy, attempt int, frac float64) time.Duration {
	d := float64(p.BaseDelay) * math.Pow(2, float64(attempt-1))
	if d > float64(p.MaxDelay) {
		d = float64(p.MaxDelay)
	}
	if p.Jitter > 0 {
		delta := d * p.Jitter
		d = d - delta + frac*2*delta
	}
	if d < 0 {
		d = 0
	}
	return time.Duration(d)
}

// Transient marks a retryable failure. RetryAfter (if > 0) overrides Backoff.
type Transient struct {
	Err        error
	RetryAfter time.Duration
}

func (e *Transient) Error() string {
	if e.Err == nil {
		return "transient error"
	}
	return e.Err.Error()
}

func (e *Transient) Unwrap() error { return e.Err }

// Operation performs one attempt; attempt is 1-based.
type Operation func(ctx context.Context, attempt int) error

// Clock is the sleep dependency, injectable for tests.
type Clock interface {
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Do retries op per the policy. A non-Transient error is terminal and returned
// immediately; a Transient waits (RetryAfter or Backoff) then retries, and
// every one counts toward MaxAttempts, so persistent throttling cannot hold the
// caller forever. Exhausting MaxAttempts returns the last error, and so does a
// RetryAfter longer than MaxDelay: the caller schedules that wait itself
// instead of sleeping on it here.
func Do(ctx context.Context, p config.RetryPolicy, op Operation) error {
	return doWith(ctx, p, op, realClock{}, rand.Float64)
}

func doWith(ctx context.Context, p config.RetryPolicy, op Operation, clk Clock, frac func() float64) error {
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := op(ctx, attempt)
		if err == nil {
			return nil
		}
		var tr *Transient
		if !errors.As(err, &tr) {
			return err // terminal
		}
		if attempt >= p.MaxAttempts || tr.RetryAfter > p.MaxDelay {
			return err
		}
		wait := tr.RetryAfter
		if wait <= 0 {
			wait = Backoff(p, attempt, frac())
		}
		if serr := clk.Sleep(ctx, wait); serr != nil {
			return serr
		}
	}
}
