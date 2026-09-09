package netdial

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRetry_SucceedsFirstAttempt 成功即返回，fn 只调用一次。
func TestRetry_SucceedsFirstAttempt(t *testing.T) {
	calls := 0
	got, err := Retry(context.Background(), 3, time.Millisecond, func() (int, error) {
		calls++
		return 42, nil
	})
	if err != nil || got != 42 {
		t.Fatalf("got=%d err=%v, want 42/<nil> (calls=%d)", got, err, calls)
	}
	if calls != 1 {
		t.Fatalf("fn called %d times, want 1", calls)
	}
}

// TestRetry_SucceedsAfterFailures 前 N-1 次失败、第 N 次成功 → 返回该值, fn 调用 N 次。
func TestRetry_SucceedsAfterFailures(t *testing.T) {
	calls := 0
	got, err := Retry(context.Background(), 3, time.Millisecond, func() (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("transient")
		}
		return "ok", nil
	})
	if err != nil || got != "ok" {
		t.Fatalf("got=%q err=%v, want \"ok\"/<nil> (calls=%d)", got, err, calls)
	}
	if calls != 3 {
		t.Fatalf("fn called %d times, want 3", calls)
	}
}

// TestRetry_FailsAllAttempts 全部失败 → 返回零值与最后一次错误, fn 调用 attempts 次。
func TestRetry_FailsAllAttempts(t *testing.T) {
	calls := 0
	sentinel := errors.New("boom")
	got, err := Retry(context.Background(), 3, time.Millisecond, func() (int, error) {
		calls++
		return 0, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v, want wrap %v", err, sentinel)
	}
	if got != 0 {
		t.Fatalf("got=%d, want 0", got)
	}
	if calls != 3 {
		t.Fatalf("fn called %d times, want 3", calls)
	}
}

// TestRetry_CancelledCtxNoCall ctx 已取消时不调用 fn, 返回 ctx.Err()。
func TestRetry_CancelledCtxNoCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	got, err := Retry(ctx, 3, time.Millisecond, func() (int, error) {
		calls++
		return 1, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
	if got != 0 {
		t.Fatalf("got=%d, want 0", got)
	}
	if calls != 0 {
		t.Fatalf("fn called %d times, want 0", calls)
	}
}
