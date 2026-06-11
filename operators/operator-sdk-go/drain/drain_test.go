package drain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPhaseConstants(t *testing.T) {
	_ = Phase(InProgress)
	_ = Phase(Complete)
	_ = Phase(TimedOut)
	_ = Phase(Failed)
}

func TestHTTPDrainClientStart(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer srv.Close()

	c := NewHTTPDrainClient("test-token")
	if err := c.Start(context.Background(), srv.URL); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", gotMethod)
	}
}

func TestHTTPDrainClientStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(DrainStatus{Phase: Complete, SessionsRemaining: 0, StartedAt: "2026-06-11T00:00:00Z"})
	}))
	defer srv.Close()

	c := NewHTTPDrainClient("")
	status, err := c.Status(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Phase != Complete {
		t.Errorf("expected Complete, got %s", status.Phase)
	}
}

func TestHTTPDrainClientStatusNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewHTTPDrainClient("")
	_, err := c.Status(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHTTPDrainClientTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewHTTPDrainClient("")
	c.client.Timeout = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := c.Status(ctx, srv.URL)
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
