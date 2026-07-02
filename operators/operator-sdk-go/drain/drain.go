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
	"net"
	"net/http"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
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
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("drain start returned %d: %s", resp.StatusCode, string(body))
	}
	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("close drain start response body: %w", err)
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
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return DrainStatus{}, fmt.Errorf("drain status returned %d: %s", resp.StatusCode, string(body))
	}
	var status DrainStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		_ = resp.Body.Close()
		return DrainStatus{}, fmt.Errorf("decode drain status: %w", err)
	}
	if err := resp.Body.Close(); err != nil {
		return DrainStatus{}, fmt.Errorf("close drain status response body: %w", err)
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

// Admin endpoint paths used by opc-runtime for drain operations.
const (
	// DrainEndpointPath is the admin path for drain start/status.
	DrainEndpointPath = "/debug/drain"
	// LivezEndpointPath is the admin liveness path.
	LivezEndpointPath = "/livez"
	// ReadyzEndpointPath is the admin readiness path.
	ReadyzEndpointPath = "/readyz"
	// StartupzEndpointPath is the admin startup path.
	StartupzEndpointPath = "/startupz"
)

// DefaultDrainPort is the conventional admin port for SDK-compatible drain
// endpoints. Products may override it via RenderOptions.AdminPort.
const DefaultDrainPort = 8080

// BuildAdminURL constructs an HTTP URL for the given admin endpoint on a pod.
// It accepts an IP (or hostname) and port, and returns a string like
// "http://10.0.0.1:8080/debug/drain". IPv6 hosts are wrapped in brackets.
// The endpoint should be one of the endpoint path constants in this package.
func BuildAdminURL(host string, port int32, endpoint string) string {
	if port == 0 {
		port = DefaultDrainPort
	}
	return fmt.Sprintf("http://%s%s", net.JoinHostPort(host, strconv.Itoa(int(port))), endpoint)
}

// PreStopDrainHook returns a LifecycleHandler that sleeps for the requested
// duration before SIGTERM reaches the container. The sleep gives the pod time
// to finish in-flight sessions and lets the workload observe drain state
// before the kernel starts tearing down sockets.
func PreStopDrainHook(delaySeconds int64) *corev1.LifecycleHandler {
	return &corev1.LifecycleHandler{
		Sleep: &corev1.SleepAction{Seconds: delaySeconds},
	}
}

// BuildPreStopLifecycle returns a Lifecycle configured with a preStop sleep
// drain hook. It is a convenience wrapper for products that want the standard
// drain hook without constructing the handler manually.
func BuildPreStopLifecycle(delaySeconds int64) *corev1.Lifecycle {
	return &corev1.Lifecycle{
		PreStop: PreStopDrainHook(delaySeconds),
	}
}
