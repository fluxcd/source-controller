/*
Copyright 2020 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	flag "github.com/spf13/pflag"
	"helm.sh/helm/v3/pkg/getter"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/fluxcd/pkg/runtime/client"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/events"
	feathelper "github.com/fluxcd/pkg/runtime/features"
	"github.com/fluxcd/pkg/runtime/leaderelection"
	"github.com/fluxcd/pkg/runtime/logger"
	"github.com/fluxcd/pkg/runtime/pprof"
	"github.com/fluxcd/pkg/runtime/probes"
	"github.com/fluxcd/source-controller/internal/features"
	"github.com/fluxcd/source-controller/internal/helm/registry"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/controllers"
	"github.com/fluxcd/source-controller/internal/cache"
	"github.com/fluxcd/source-controller/internal/helm"
	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/libgit2/managed"
	// +kubebuilder:scaffold:imports
)

const controllerName = "source-controller"

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
	getters  = getter.Providers{
		getter.Provider{
			Schemes: []string{"http", "https"},
			New:     getter.NewHTTPGetter,
		},
		getter.Provider{
			Schemes: []string{"oci"},
			New:     getter.NewOCIGetter,
		},
	}
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(sourcev1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var (
		metricsAddr              string
		eventsAddr               string
		healthAddr               string
		storagePath              string
		storageAddr              string
		storageAdvAddr           string
		concurrent               int
		requeueDependency        time.Duration
		watchAllNamespaces       bool
		helmIndexLimit           int64
		helmChartLimit           int64
		helmChartFileLimit       int64
		clientOptions            client.Options
		logOptions               logger.Options
		leaderElectionOptions    leaderelection.Options
		rateLimiterOptions       helper.RateLimiterOptions
		featureGates             feathelper.FeatureGates
		helmCacheMaxSize         int
		helmCacheTTL             string
		helmCachePurgeInterval   string
		artifactRetentionTTL     time.Duration
		artifactRetentionRecords int
	)

	flag.StringVar(&metricsAddr, "metrics-addr", envOrDefault("METRICS_ADDR", ":8080"),
		"The address the metric endpoint binds to.")
	flag.StringVar(&eventsAddr, "events-addr", envOrDefault("EVENTS_ADDR", ""),
		"The address of the events receiver.")
	flag.StringVar(&healthAddr, "health-addr", ":9440", "The address the health endpoint binds to.")
	flag.StringVar(&storagePath, "storage-path", envOrDefault("STORAGE_PATH", ""),
		"The local storage path.")
	flag.StringVar(&storageAddr, "storage-addr", envOrDefault("STORAGE_ADDR", ":9090"),
		"The address the static file server binds to.")
	flag.StringVar(&storageAdvAddr, "storage-adv-addr", envOrDefault("STORAGE_ADV_ADDR", ""),
		"The advertised address of the static file server.")
	flag.IntVar(&concurrent, "concurrent", 2, "The number of concurrent reconciles per controller.")
	flag.BoolVar(&watchAllNamespaces, "watch-all-namespaces", true,
		"Watch for custom resources in all namespaces, if set to false it will only watch the runtime namespace.")
	flag.Int64Var(&helmIndexLimit, "helm-index-max-size", helm.MaxIndexSize,
		"The max allowed size in bytes of a Helm repository index file.")
	flag.Int64Var(&helmChartLimit, "helm-chart-max-size", helm.MaxChartSize,
		"The max allowed size in bytes of a Helm chart file.")
	flag.Int64Var(&helmChartFileLimit, "helm-chart-file-max-size", helm.MaxChartFileSize,
		"The max allowed size in bytes of a file in a Helm chart.")
	flag.DurationVar(&requeueDependency, "requeue-dependency", 30*time.Second,
		"The interval at which failing dependencies are reevaluated.")
	flag.IntVar(&helmCacheMaxSize, "helm-cache-max-size", 0,
		"The maximum size of the cache in number of indexes.")
	flag.StringVar(&helmCacheTTL, "helm-cache-ttl", "15m",
		"The TTL of an index in the cache. Valid time units are ns, us (or µs), ms, s, m, h.")
	flag.StringVar(&helmCachePurgeInterval, "helm-cache-purge-interval", "1m",
		"The interval at which the cache is purged. Valid time units are ns, us (or µs), ms, s, m, h.")
	flag.StringSliceVar(&git.KexAlgos, "ssh-kex-algos", []string{},
		"The list of key exchange algorithms to use for ssh connections, arranged from most preferred to the least.")
	flag.StringSliceVar(&git.HostKeyAlgos, "ssh-hostkey-algos", []string{},
		"The list of hostkey algorithms to use for ssh connections, arranged from most preferred to the least.")
	flag.DurationVar(&artifactRetentionTTL, "artifact-retention-ttl", 60*time.Second,
		"The duration of time that artifacts will be kept in storage before being garbage collected.")
	flag.IntVar(&artifactRetentionRecords, "artifact-retention-records", 2,
		"The maximum number of artifacts to be kept in storage after a garbage collection.")

	clientOptions.BindFlags(flag.CommandLine)
	logOptions.BindFlags(flag.CommandLine)
	leaderElectionOptions.BindFlags(flag.CommandLine)
	rateLimiterOptions.BindFlags(flag.CommandLine)
	featureGates.BindFlags(flag.CommandLine)

	flag.Parse()

	ctrl.SetLogger(logger.NewLogger(logOptions))

	err := featureGates.WithLogger(setupLog).
		SupportedFeatures(features.FeatureGates())

	if err != nil {
		setupLog.Error(err, "unable to load feature gates")
		os.Exit(1)
	}

	// Set upper bound file size limits Helm
	helm.MaxIndexSize = helmIndexLimit
	helm.MaxChartSize = helmChartLimit
	helm.MaxChartFileSize = helmChartFileLimit

	watchNamespace := ""
	if !watchAllNamespaces {
		watchNamespace = os.Getenv("RUNTIME_NAMESPACE")
	}

	restConfig := client.GetConfigOrDie(clientOptions)
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                        scheme,
		MetricsBindAddress:            metricsAddr,
		HealthProbeBindAddress:        healthAddr,
		Port:                          9443,
		LeaderElection:                leaderElectionOptions.Enable,
		LeaderElectionReleaseOnCancel: leaderElectionOptions.ReleaseOnCancel,
		LeaseDuration:                 &leaderElectionOptions.LeaseDuration,
		RenewDeadline:                 &leaderElectionOptions.RenewDeadline,
		RetryPeriod:                   &leaderElectionOptions.RetryPeriod,
		LeaderElectionID:              fmt.Sprintf("%s-leader-election", controllerName),
		Namespace:                     watchNamespace,
		Logger:                        ctrl.Log,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	probes.SetupChecks(mgr, setupLog)
	pprof.SetupHandlers(mgr, setupLog)

	var eventRecorder *events.Recorder
	if eventRecorder, err = events.NewRecorder(mgr, ctrl.Log, eventsAddr, controllerName); err != nil {
		setupLog.Error(err, "unable to create event recorder")
		os.Exit(1)
	}

	metricsH := helper.MustMakeMetrics(mgr)

	if storageAdvAddr == "" {
		storageAdvAddr = determineAdvStorageAddr(storageAddr, setupLog)
	}
	storage := mustInitStorage(storagePath, storageAdvAddr, artifactRetentionTTL, artifactRetentionRecords, setupLog)

	if err = (&controllers.GitRepositoryReconciler{
		Client:         mgr.GetClient(),
		EventRecorder:  eventRecorder,
		Metrics:        metricsH,
		Storage:        storage,
		ControllerName: controllerName,
	}).SetupWithManagerAndOptions(mgr, controllers.GitRepositoryReconcilerOptions{
		MaxConcurrentReconciles:   concurrent,
		DependencyRequeueInterval: requeueDependency,
		RateLimiter:               helper.GetRateLimiter(rateLimiterOptions),
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", sourcev1.GitRepositoryKind)
		os.Exit(1)
	}
	if err = (&controllers.HelmRepositoryReconciler{
		Client:         mgr.GetClient(),
		EventRecorder:  eventRecorder,
		Metrics:        metricsH,
		Storage:        storage,
		Getters:        getters,
		ControllerName: controllerName,
	}).SetupWithManagerAndOptions(mgr, controllers.HelmRepositoryReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
		RateLimiter:             helper.GetRateLimiter(rateLimiterOptions),
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", sourcev1.HelmRepositoryKind, "type", "default")
		os.Exit(1)
	}

	if err = (&controllers.HelmRepositoryOCIReconciler{
		Client:                  mgr.GetClient(),
		EventRecorder:           eventRecorder,
		Metrics:                 metricsH,
		Getters:                 getters,
		ControllerName:          controllerName,
		RegistryClientGenerator: registry.ClientGenerator,
	}).SetupWithManagerAndOptions(mgr, controllers.HelmRepositoryReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
		RateLimiter:             helper.GetRateLimiter(rateLimiterOptions),
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", sourcev1.HelmRepositoryKind, "type", "OCI")
		os.Exit(1)
	}

	var c *cache.Cache
	var ttl time.Duration
	if helmCacheMaxSize > 0 {
		interval, err := time.ParseDuration(helmCachePurgeInterval)
		if err != nil {
			setupLog.Error(err, "unable to parse cache purge interval")
			os.Exit(1)
		}

		ttl, err = time.ParseDuration(helmCacheTTL)
		if err != nil {
			setupLog.Error(err, "unable to parse cache TTL")
			os.Exit(1)
		}

		c = cache.New(helmCacheMaxSize, interval)
	}

	cacheRecorder := cache.MustMakeMetrics()

	if err = (&controllers.HelmChartReconciler{
		Client:                  mgr.GetClient(),
		RegistryClientGenerator: registry.ClientGenerator,
		Storage:                 storage,
		Getters:                 getters,
		EventRecorder:           eventRecorder,
		Metrics:                 metricsH,
		ControllerName:          controllerName,
		Cache:                   c,
		TTL:                     ttl,
		CacheRecorder:           cacheRecorder,
	}).SetupWithManagerAndOptions(mgr, controllers.HelmChartReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
		RateLimiter:             helper.GetRateLimiter(rateLimiterOptions),
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", sourcev1.HelmChartKind)
		os.Exit(1)
	}
	if err = (&controllers.BucketReconciler{
		Client:         mgr.GetClient(),
		EventRecorder:  eventRecorder,
		Metrics:        metricsH,
		Storage:        storage,
		ControllerName: controllerName,
	}).SetupWithManagerAndOptions(mgr, controllers.BucketReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
		RateLimiter:             helper.GetRateLimiter(rateLimiterOptions),
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Bucket")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	go func() {
		// Block until our controller manager is elected leader. We presume our
		// entire process will terminate if we lose leadership, so we don't need
		// to handle that.
		<-mgr.Elected()

		startFileServer(storage.BasePath, storageAddr, setupLog)
	}()

	if enabled, _ := features.Enabled(features.GitManagedTransport); enabled {
		managed.InitManagedTransport()
	} else {
		if optimize, _ := feathelper.Enabled(features.OptimizedGitClones); optimize {
			features.Disable(features.OptimizedGitClones)
			setupLog.Info(
				"disabling optimized git clones; git clones can only be optimized when using managed transport",
			)
		}
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func startFileServer(path string, address string, l logr.Logger) {
	l.Info("starting file server")
	fs := http.FileServer(http.Dir(path))
	http.Handle("/", fs)
	err := http.ListenAndServe(address, nil)
	if err != nil {
		l.Error(err, "file server error")
	}
}

func mustInitStorage(path string, storageAdvAddr string, artifactRetentionTTL time.Duration, artifactRetentionRecords int, l logr.Logger) *controllers.Storage {
	if path == "" {
		p, _ := os.Getwd()
		path = filepath.Join(p, "bin")
		os.MkdirAll(path, 0o770)
	}

	storage, err := controllers.NewStorage(path, storageAdvAddr, artifactRetentionTTL, artifactRetentionRecords)
	if err != nil {
		l.Error(err, "unable to initialise storage")
		os.Exit(1)
	}

	return storage
}

func determineAdvStorageAddr(storageAddr string, l logr.Logger) string {
	host, port, err := net.SplitHostPort(storageAddr)
	if err != nil {
		l.Error(err, "unable to parse storage address")
		os.Exit(1)
	}
	switch host {
	case "":
		host = "localhost"
	case "0.0.0.0":
		host = os.Getenv("HOSTNAME")
		if host == "" {
			hn, err := os.Hostname()
			if err != nil {
				l.Error(err, "0.0.0.0 specified in storage addr but hostname is invalid")
				os.Exit(1)
			}
			host = hn
		}
	}
	return net.JoinHostPort(host, port)
}

func envOrDefault(envName, defaultValue string) string {
	ret := os.Getenv(envName)
	if ret != "" {
		return ret
	}

	return defaultValue
}
