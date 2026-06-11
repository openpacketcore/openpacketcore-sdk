// Package drain orchestrates graceful shutdown of CNF pods via the
// opc-runtime admin drain endpoints.
//
// It defines an Orchestrator interface, provides an HTTP-based implementation,
// and integrates with the reference reconciler to drive the Draining phase
// and finalizer.
package drain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Phase represents the current state of a drain operation.
type Phase string

const (
	InProgress Phase = "InProgress"
	Complete   Phase = "Complete"
	TimedOut   Phase = "TimedOut"
	Failed     Phase = "Failed"
)

// DrainStatus reports the state of an in-flight drain.
type DrainStatus struct {
	Phase             Phase  `json:"phase"`
	SessionsRemaining int64  `json:"sessions_remaining"`
	StartedAt         string `json:"started_at"`
}

// Orchestrator drives drain lifecycle for a target CNF.
type Orchestrator interface {
	Start(ctx context.Context, target string) error
	Status(ctx context.Context, target string) (DrainStatus, error)
}

// HTTPDrainClient implements Orchestrator against opc-runtime admin endpoints.
type HTTPDrainClient struct {
	client    *http.Client
	authToken string
}

// NewHTTPDrainClient creates an HTTP drain client.
func NewHTTPDrainClient(authToken string) *HTTPDrainClient {
	return &HTTPDrainClient{
		client:    &http.Client{Timeout: 10 * time.Second},
		authToken: authToken,
	}
}

// Start triggers drain by POSTing to the admin /debug/drain endpoint.
func (c *HTTPDrainClient) Start(ctx context.Context, target string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target+"/debug/drain", nil)
	if err != nil {
		return fmt.Errorf("build drain start request: %w", err)
	}
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("drain start request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("drain start returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// Status polls the admin /debug/drain endpoint.
func (c *HTTPDrainClient) Status(ctx context.Context, target string) (DrainStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+"/debug/drain", nil)
	if err != nil {
		return DrainStatus{}, fmt.Errorf("build drain status request: %w", err)
	}
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return DrainStatus{}, fmt.Errorf("drain status request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return DrainStatus{}, fmt.Errorf("drain status returned %d: %s", resp.StatusCode, string(body))
	}
	var status DrainStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return DrainStatus{}, fmt.Errorf("decode drain status: %w", err)
	}
	return status, nil
}

// FakeOrchestrator is a test double that returns canned responses.
type FakeOrchestrator struct {
	StartFunc  func(ctx context.Context, target string) error
	StatusFunc func(ctx context.Context, target string) (DrainStatus, error)
}

func (f *FakeOrchestrator) Start(ctx context.Context, target string) error {
	if f.StartFunc != nil {
		return f.StartFunc(ctx, target)
	}
	return nil
}

func (f *FakeOrchestrator) Status(ctx context.Context, target string) (DrainStatus, error) {
	if f.StatusFunc != nil {
		return f.StatusFunc(ctx, target)
	}
	return DrainStatus{Phase: Complete}, nil
}
