#!/bin/sh
set -eu

: "${GOTOOLCHAIN:=go1.26.4}"
export GOTOOLCHAIN

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=${TMPDIR:-/tmp}
TMP=$(mktemp -d "${TMP%/}/operator-sdk-go-downstream.XXXXXX")
trap 'rm -rf "$TMP"' EXIT INT TERM

DOWNSTREAM="$TMP/downstream"
mkdir -p "$DOWNSTREAM"

cat > "$DOWNSTREAM/go.mod" <<'EOF'
module example.com/downstream-operator

go 1.26.4
EOF

cat > "$DOWNSTREAM/imports_test.go" <<'EOF'
package downstream

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"openpacketcore.io/operator-sdk-go/bridge"
	"openpacketcore.io/operator-sdk-go/cni"
	"openpacketcore.io/operator-sdk-go/conditions"
	"openpacketcore.io/operator-sdk-go/drain"
	"openpacketcore.io/operator-sdk-go/gates"
	"openpacketcore.io/operator-sdk-go/opmetrics"
	"openpacketcore.io/operator-sdk-go/rollout"
	sdktesting "openpacketcore.io/operator-sdk-go/testing"
	"openpacketcore.io/operator-sdk-go/workload"
)

func TestStableImports(t *testing.T) {
	cm := conditions.NewConditionManager(7)
	if err := conditions.GateCondition(cm, conditions.GateListeners, conditions.GatePassing, conditions.GateReason(conditions.GateListeners, conditions.GatePassing), conditions.GateMessage(conditions.GateListeners, conditions.GatePassing), 7); err != nil {
		t.Fatalf("set gate condition: %v", err)
	}

	attachments := cni.BuildAttachments([]string{"n3"}, func(name string) cni.Attachment {
		return cni.Attachment{NetworkName: name, InterfaceName: name}
	})
	if len(attachments) != 1 {
		t.Fatalf("unexpected attachments: %d", len(attachments))
	}

	status, err := (&drain.FakeOrchestrator{}).Status(context.Background(), drain.BuildAdminURL("127.0.0.1", drain.DefaultDrainPort, drain.DrainEndpointPath))
	if err != nil || status.Phase != drain.Complete {
		t.Fatalf("unexpected drain status: %v %v", status, err)
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Generation: 1},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 1,
			Replicas:           1,
			UpdatedReplicas:    1,
			ReadyReplicas:      1,
			AvailableReplicas:  1,
		},
	}
	if !gates.DeploymentIsReady(deployment, 1) {
		t.Fatal("deployment should be ready")
	}

	maxUnavailable := intstr.FromInt(0)
	if _, err := rollout.BuildDeploymentStrategy(rollout.Params{
		Strategy:       rollout.StrategyCanary,
		MaxUnavailable: &maxUnavailable,
	}); err != nil {
		t.Fatalf("build rollout strategy: %v", err)
	}

	opts := workload.DefaultRenderOptions()
	opts.Image = "openpacketcore/example:v1.0.0"
	rendered, err := workload.RenderDeployment(workload.NetworkFunctionSpec{
		Name:      "example",
		Namespace: "default",
		Version:   "v1.0.0",
		AdditionalPorts: []workload.PortSpec{
			{Name: "ike", Port: 500, Protocol: string(corev1.ProtocolUDP)},
		},
	}, opts)
	if err != nil || rendered.Name != "example" {
		t.Fatalf("render workload: %v %v", rendered, err)
	}

	_ = bridge.ExpectedContractVersion
	_ = bridge.WithDefaultTimeout(time.Second)
	_ = opmetrics.ReconcileTotal
	if got := (&sdktesting.FakeClock{}).Now(); got == "" {
		t.Fatal("fake clock returned empty time")
	}
}
EOF

cat > "$TMP/go.work" <<EOF
go 1.26.4

use (
	$ROOT
	$DOWNSTREAM
)
EOF

if grep -Eq '^[[:space:]]*replace[[:space:]]' "$DOWNSTREAM/go.mod"; then
	echo "downstream fixture must not use replace directives" >&2
	exit 1
fi

(cd "$DOWNSTREAM" && GOWORK="$TMP/go.work" go test ./...)
