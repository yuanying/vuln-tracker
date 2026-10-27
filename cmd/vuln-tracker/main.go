// Command vuln-tracker follows how far the fix for each vulnerability of the
// images running in the cluster has got, lays fleet-infra's OpenVEX
// annotations over them, and exports the result as metrics and a weekly
// Slack digest (ADR 0001).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	// The image has no zoneinfo; review-by dates and the digest schedule
	// are read in a named time zone.
	_ "time/tzdata"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/yuanying/vuln-tracker/internal/config"
	"github.com/yuanying/vuln-tracker/internal/digest"
	"github.com/yuanying/vuln-tracker/internal/github"
	"github.com/yuanying/vuln-tracker/internal/registry"
	"github.com/yuanying/vuln-tracker/internal/scanner"
	"github.com/yuanying/vuln-tracker/internal/state"
	"github.com/yuanying/vuln-tracker/internal/tracker"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(corev1.AddToScheme(scheme))
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	zapOpts := zap.Options{}
	cfg, err := config.Parse(args, os.Getenv, func(fs *flag.FlagSet) { zapOpts.BindFlags(fs) })
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))
	log := ctrl.Log.WithName("vuln-tracker")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions(cfg))
	if err != nil {
		return fmt.Errorf("building the manager: %w", err)
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("registering the health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("registering the readiness check: %w", err)
	}

	t := newTracker(mgr, cfg)
	if err := watch(mgr, t); err != nil {
		return err
	}
	if err := mgr.Add(t); err != nil {
		return fmt.Errorf("adding the tracker: %w", err)
	}
	ctrlmetrics.Registry.MustRegister(&tracker.Collector{DetailSeverities: cfg.DetailSeverities, Snapshot: t.Snapshot})

	log.Info("starting", "trivyServer", cfg.TrivyServer, "fleetInfra", cfg.FleetInfra.Name, "detailSeverities", cfg.DetailSeverities)
	return mgr.Start(ctrl.SetupSignalHandler())
}

func managerOptions(cfg config.Config) ctrl.Options {
	return ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: cfg.MetricsAddr},
		HealthProbeBindAddress: cfg.ProbeAddr,
		LeaderElection:         cfg.LeaderElect,
		LeaderElectionID:       "vuln-tracker",
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				// Every Pod in the cluster is cached, so only what says
				// which digests run is kept (ADR 0007).
				&corev1.Pod{}: {Transform: tracker.StripPod},
			},
		},
		Client: client.Options{
			Cache: &client.CacheOptions{
				// The state ConfigMap is read straight from the API
				// server: the RBAC grants that one ConfigMap by name,
				// which a cluster-wide informer could not list.
				DisableFor: []client.Object{&corev1.ConfigMap{}},
			},
		},
	}
}

func newTracker(mgr manager.Manager, cfg config.Config) *tracker.Tracker {
	var slack tracker.Sender
	if cfg.SlackWebhookURL != "" {
		slack = &digest.Slack{WebhookURL: cfg.SlackWebhookURL, HTTP: &http.Client{Timeout: 30 * time.Second}}
	}
	return &tracker.Tracker{
		Source: &tracker.ClusterSource{Reader: mgr.GetCache()},
		Store:  &state.ConfigMapStore{Client: mgr.GetClient(), Namespace: cfg.Namespace, Name: cfg.StateConfigMap},
		Discoverer: &tracker.Discoverer{
			Registry:         &registry.Remote{},
			SelfSourcePrefix: cfg.SelfSourcePrefix,
			RenovateAuthor:   cfg.RenovateAuthor,
		},
		Scanner: &scanner.Trivy{
			Binary:    cfg.TrivyBinary,
			ServerURL: cfg.TrivyServer,
			Token:     cfg.TrivyToken,
			CacheDir:  cfg.TrivyCacheDir,
			TempDir:   cfg.TrivyTempDir,
			Timeout:   cfg.ScanTimeout,
		},
		GitHub:  &github.Client{Token: cfg.GitHubToken, HTTP: &http.Client{Timeout: 2 * time.Minute}},
		Slack:   slack,
		Metrics: tracker.NewMetrics(ctrlmetrics.Registry),
		Log:     ctrl.Log.WithName("tracker"),
		Config: tracker.Config{
			FleetInfra:       cfg.FleetInfra,
			Manifests:        cfg.Manifests,
			DetailSeverities: cfg.DetailSeverities,
			Location:         cfg.Location,
			Schedule:         cfg.Schedule,
			DashboardURL:     cfg.DashboardURL,
			VEXBaseURL:       cfg.VEXBaseURL,
			GitInterval:      cfg.GitInterval,
			ScanInterval:     cfg.ScanInterval,
		},
	}
}

// watch asks for an evaluation whenever a VulnerabilityReport or a Pod
// changes, so a retaken report shows without waiting for the next minute.
func watch(mgr manager.Manager, t *tracker.Tracker) error {
	poke := toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { t.Trigger() },
		UpdateFunc: func(any, any) { t.Trigger() },
		DeleteFunc: func(any) { t.Trigger() },
	}
	vr := &unstructured.Unstructured{}
	vr.SetGroupVersionKind(tracker.VulnerabilityReportGVK)
	for _, obj := range []client.Object{vr, &corev1.Pod{}} {
		inf, err := mgr.GetCache().GetInformer(context.Background(), obj, cache.BlockUntilSynced(false))
		if err != nil {
			return fmt.Errorf("watching %T: %w", obj, err)
		}
		if _, err := inf.AddEventHandler(poke); err != nil {
			return fmt.Errorf("watching %T: %w", obj, err)
		}
	}
	return nil
}
