package drain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func clientWithHandler(authToken string, handler http.HandlerFunc) *HTTPDrainClient {
	c := NewHTTPDrainClient(authToken)
	c.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Result(), nil
	})
	return c
}

func TestPhaseConstants(t *testing.T) {
	_ = Phase(InProgress)
	_ = Phase(Complete)
	_ = Phase(TimedOut)
	_ = Phase(Failed)
}

func TestHTTPDrainClientStart(t *testing.T) {
	var gotMethod string
	c := clientWithHandler("test-token", func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		if r.URL.Path != "/debug/drain" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(DrainStatus{Phase: InProgress})
	})

	if err := c.Start(context.Background(), "http://drain.local"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", gotMethod)
	}
}

func TestHTTPDrainClientStatus(t *testing.T) {
	c := clientWithHandler("", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(DrainStatus{Phase: Complete, SessionsRemaining: 0, StartedAt: "2026-06-11T00:00:00Z"})
	})

	status, err := c.Status(context.Background(), "http://drain.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Phase != Complete {
		t.Errorf("expected Complete, got %s", status.Phase)
	}
}

func TestHTTPDrainClientStatusNonOK(t *testing.T) {
	c := clientWithHandler("", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})

	_, err := c.Status(context.Background(), "http://drain.local")
	if err == nil {
		t.Fatal("expected error")
	}
}

type errorCloseBody struct {
	io.Reader
}

func (errorCloseBody) Close() error { return errors.New("close failed") }

func clientWithErrorCloseBody(payload string) *HTTPDrainClient {
	c := NewHTTPDrainClient("")
	c.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       errorCloseBody{strings.NewReader(payload)},
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	return c
}

func TestHTTPDrainClientIgnoresBodyCloseError(t *testing.T) {
	c := clientWithErrorCloseBody(`{"phase":"Complete"}`)

	if err := c.Start(context.Background(), "http://drain.local"); err != nil {
		t.Fatalf("Start must ignore response body close errors, got %v", err)
	}

	status, err := c.Status(context.Background(), "http://drain.local")
	if err != nil {
		t.Fatalf("Status must ignore response body close errors, got %v", err)
	}
	if status.Phase != Complete {
		t.Errorf("expected Complete, got %s", status.Phase)
	}
}

func TestHTTPDrainClientTimeout(t *testing.T) {
	c := NewHTTPDrainClient("")
	c.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	c.client.Timeout = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := c.Status(ctx, "http://drain.local")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestFakeOrchestrator(t *testing.T) {
	f := &FakeOrchestrator{
		StatusFunc: func(ctx context.Context, target string) (DrainStatus, error) {
			return DrainStatus{Phase: InProgress}, nil
		},
	}
	status, err := f.Status(context.Background(), "http://test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Phase != InProgress {
		t.Errorf("expected InProgress, got %s", status.Phase)
	}
}

func TestFakeOrchestratorStartError(t *testing.T) {
	f := &FakeOrchestrator{
		StartFunc: func(ctx context.Context, target string) error {
			return fmt.Errorf("start failed")
		},
	}
	if err := f.Start(context.Background(), "http://test"); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildAdminURL(t *testing.T) {
	got := BuildAdminURL("10.0.0.1", 9090, DrainEndpointPath)
	want := "http://10.0.0.1:9090/debug/drain"
	if got != want {
		t.Errorf("BuildAdminURL() = %q, want %q", got, want)
	}
	got = BuildAdminURL("10.0.0.1", 0, ReadyzEndpointPath)
	want = "http://10.0.0.1:8080/readyz"
	if got != want {
		t.Errorf("BuildAdminURL() default port = %q, want %q", got, want)
	}
	got = BuildAdminURL("fd00::1", 8080, DrainEndpointPath)
	want = "http://[fd00::1]:8080/debug/drain"
	if got != want {
		t.Errorf("BuildAdminURL() IPv6 = %q, want %q", got, want)
	}
}

func TestPreStopDrainHook(t *testing.T) {
	hook := PreStopDrainHook(5)
	if hook == nil || hook.Sleep == nil {
		t.Fatal("expected preStop sleep hook")
	}
	if hook.Sleep.Seconds != 5 {
		t.Errorf("expected sleep seconds 5, got %d", hook.Sleep.Seconds)
	}
}

func TestBuildPreStopLifecycle(t *testing.T) {
	lc := BuildPreStopLifecycle(10)
	if lc == nil || lc.PreStop == nil || lc.PreStop.Sleep == nil {
		t.Fatal("expected preStop lifecycle")
	}
	if lc.PreStop.Sleep.Seconds != 10 {
		t.Errorf("expected sleep seconds 10, got %d", lc.PreStop.Sleep.Seconds)
	}
}
