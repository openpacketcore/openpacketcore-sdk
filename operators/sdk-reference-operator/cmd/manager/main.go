package main

import (
	"crypto/tls"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run works without extra imports.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	apiv1alpha1 "openpacketcore.io/sdk-reference-operator/api/v1alpha1"
	apiv1beta1 "openpacketcore.io/sdk-reference-operator/api/v1beta1"
	"openpacketcore.io/sdk-reference-operator/internal/controller"
	"openpacketcore.io/sdk-reference-operator/internal/sdkbridge"
	"openpacketcore.io/sdk-reference-operator/internal/webhook"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	webhookserver "sigs.k8s.io/controller-runtime/pkg/webhook"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(apiv1alpha1.AddToScheme(scheme))
	utilruntime.Must(apiv1beta1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metric endpoint binds to. Use :8080 for active metrics.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", false,
		"If set the metrics endpoint is served securely")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Initialize SDK Bridge
	bridge, err := sdkbridge.NewBridge()
	if err != nil {
		setupLog.Error(err, "unable to initialize SDK bridge")
		os.Exit(1)
	}

	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http2")
		c.NextProtos = []string{"http/1.1"}
	}

	var webhookServer webhookserver.Server
	if !enableHTTP2 {
		webhookServer = webhookserver.NewServer(webhookserver.Options{
			TLSOpts: []func(*tls.Config){disableHTTP2},
		})
	} else {
		webhookServer = webhookserver.NewServer(webhookserver.Options{})
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "sdk-reference-operator-leader.openpacketcore.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Register Reconciler
	if err = (&controller.SdkManagedNetworkFunctionReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Bridge: bridge,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SdkManagedNetworkFunction")
		os.Exit(1)
	}

	// Register Validating Webhook
	if err = (&webhook.SdkManagedNetworkFunctionValidator{
		Client: mgr.GetClient(),
		Bridge: bridge,
	}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "SdkManagedNetworkFunction")
		os.Exit(1)
	}

	// Register Conversion Webhook
	if err = ctrl.NewWebhookManagedBy(mgr, &apiv1beta1.SdkManagedNetworkFunction{}).
		Complete(); err != nil {
		setupLog.Error(err, "unable to create conversion webhook", "webhook", "SdkManagedNetworkFunction")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
