package transfer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/pkg/config"
)

func TestBackoffGrowthNoJitter(t *testing.T) {
	p := config.RetryPolicy{BaseDelay: 100 * time.Millisecond, MaxDelay: 10 * time.Second, Jitter: 0}
	want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond}
	for i, w := range want {
		if got := Backoff(p, i+1, 0); got != w {
			t.Errorf("attempt %d: got %v want %v", i+1, got, w)
		}
	}
}

func TestBackoffCappedAtMaxDelay(t *testing.T) {
	p := config.RetryPolicy{BaseDelay: time.Second, MaxDelay: 3 * time.Second, Jitter: 0}
	if got := Backoff(p, 10, 0); got != 3*time.Second {
		t.Errorf("got %v want cap 3s", got)
	}
}

func TestBackoffJitterBounds(t *testing.T) {
	p := config.RetryPolicy{BaseDelay: time.Second, MaxDelay: time.Minute, Jitter: 0.2}
	if got := Backoff(p, 1, 0); got != 800*time.Millisecond {
		t.Errorf("frac=0 got %v want 800ms", got)
	}
	if got := Backoff(p, 1, 0.5); got != time.Second {
		t.Errorf("frac=0.5 got %v want 1s", got)
	}
}

func TestTransientErrorAndUnwrap(t *testing.T) {
	if got := (&Transient{Err: errors.New("boom")}).Error(); got != "boom" {
		t.Errorf("Error() got %q want boom", got)
	}
	if got := (&Transient{}).Error(); got != "transient error" {
		t.Errorf("nil-Err Error() got %q want 'transient error'", got)
	}
	var err error = &Transient{Err: errors.New("inner")}
	if u := errors.Unwrap(err); u == nil || u.Error() != "inner" {
		t.Errorf("Unwrap() got %v want inner", u)
	}
}

type fakeClock struct{ slept []time.Duration }

func (f *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.slept = append(f.slept, d)
	return nil
}

// errClock always returns err from Sleep, simulating a failure (e.g. ctx
// cancellation) that occurs DURING the wait.
type errClock struct{ err error }

func (c errClock) Sleep(ctx context.Context, d time.Duration) error { return c.err }

func policy(maxAttempts int) config.RetryPolicy {
	p := config.DefaultRetryPolicy()
	p.MaxAttempts = maxAttempts
	p.Jitter = 0
	return p
}

func TestDoSucceedsFirstTry(t *testing.T) {
	calls := 0
	err := doWith(context.Background(), policy(3),
		func(ctx context.Context, attempt int) error { calls++; return nil },
		&fakeClock{}, func() float64 { return 0 })
	if err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestDoRetriesTransientThenSucceeds(t *testing.T) {
	calls := 0
	err := doWith(context.Background(), policy(5), func(ctx context.Context, attempt int) error {
		calls++
		if calls < 3 {
			return &Transient{Err: errors.New("flaky")}
		}
		return nil
	}, &fakeClock{}, func() float64 { return 0 })
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestDoTerminalErrorReturnsImmediately(t *testing.T) {
	sentinel := errors.New("terminal")
	calls := 0
	err := doWith(context.Background(), policy(5), func(ctx context.Context, attempt int) error {
		calls++
		return sentinel
	}, &fakeClock{}, func() float64 { return 0 })
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestDoExhaustsMaxAttempts(t *testing.T) {
	calls := 0
	err := doWith(context.Background(), policy(3), func(ctx context.Context, attempt int) error {
		calls++
		return &Transient{Err: errors.New("always")}
	}, &fakeClock{}, func() float64 { return 0 })
	if err == nil || calls != 3 {
		t.Fatalf("err=%v calls=%d (want 3)", err, calls)
	}
	var tr *Transient
	if !errors.As(err, &tr) {
		t.Fatalf("exhausted error should unwrap to the last *Transient, got %T: %v", err, err)
	}
	if tr.Err.Error() != "always" {
		t.Fatalf("want last transient err 'always', got %q", tr.Err.Error())
	}
}

func TestDoThrottleDoesNotConsumeBudget(t *testing.T) {
	calls := 0
	clk := &fakeClock{}
	err := doWith(context.Background(), policy(1), func(ctx context.Context, attempt int) error {
		calls++
		if calls <= 2 {
			return &Transient{Err: errors.New("429"), RetryAfter: 2 * time.Second, Throttle: true}
		}
		return nil
	}, clk, func() float64 { return 0 })
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d (want 3)", err, calls)
	}
	if len(clk.slept) != 2 || clk.slept[0] != 2*time.Second {
		t.Fatalf("expected two 2s Retry-After sleeps, got %v", clk.slept)
	}
}

func TestDoContextCanceledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := doWith(ctx, policy(5), func(ctx context.Context, attempt int) error {
		return &Transient{Err: errors.New("x")}
	}, &fakeClock{}, func() float64 { return 0 })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestDoReturnsClockSleepError(t *testing.T) {
	calls := 0
	err := doWith(context.Background(), policy(5), func(ctx context.Context, attempt int) error {
		calls++
		return &Transient{Err: errors.New("flaky")}
	}, errClock{err: context.Canceled}, func() float64 { return 0 })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled from clock, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("op should run once before the sleep error surfaces, got %d", calls)
	}
}

func TestDoRealClockRetriesViaPublicEntrypoint(t *testing.T) {
	p := policy(5)
	p.BaseDelay = time.Millisecond
	p.MaxDelay = 5 * time.Millisecond
	calls := 0
	err := Do(context.Background(), p, func(ctx context.Context, attempt int) error {
		calls++
		if calls < 2 {
			return &Transient{Err: errors.New("once")}
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("err=%v calls=%d (want 2)", err, calls)
	}
}
