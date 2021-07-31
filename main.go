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
	"strings"
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
	"github.com/fluxcd/pkg/runtime/leaderelection"
	"github.com/fluxcd/pkg/runtime/logger"
	"github.com/fluxcd/pkg/runtime/pprof"
	"github.com/fluxcd/pkg/runtime/probes"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/controllers"
	"github.com/fluxcd/source-controller/internal/helm"
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
	}
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(sourcev1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var (
		metricsAddr           string
		eventsAddr            string
		healthAddr            string
		storagePath           string
		storageAddr           string
		storageAdvAddr        string
		concurrent            int
		requeueDependency     time.Duration
		watchAllNamespaces    bool
		helmIndexLimit        int64
		helmChartLimit        int64
		helmChartFileLimit    int64
		clientOptions         client.Options
		logOptions            logger.Options
		leaderElectionOptions leaderelection.Options
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

	clientOptions.BindFlags(flag.CommandLine)
	logOptions.BindFlags(flag.CommandLine)
	leaderElectionOptions.BindFlags(flag.CommandLine)

	flag.Parse()

	ctrl.SetLogger(logger.NewLogger(logOptions))

	// Set upper bound file size limits Helm
	helm.MaxIndexSize = helmIndexLimit
	helm.MaxChartSize = helmChartLimit
	helm.MaxChartFileSize = helmChartFileLimit

	var eventRecorder *events.Recorder
	if eventsAddr != "" {
		var err error
		if eventRecorder, err = events.NewRecorder(eventsAddr, controllerName); err != nil {
			setupLog.Error(err, "unable to create event recorder")
			os.Exit(1)
		}
	}

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

	eventsH := helper.MakeEvents(mgr, controllerName, eventRecorder)
	metricsH := helper.MustMakeMetrics(mgr)

	// NOTE: Temporarily, to be able to keep reconcilers-dev branches in sync.
	_ = eventsH

	if storageAdvAddr == "" {
		storageAdvAddr = determineAdvStorageAddr(storageAddr, setupLog)
	}
	storage := mustInitStorage(storagePath, storageAdvAddr, setupLog)

	if err = (&controllers.GitRepositoryReconciler{
		Client:                mgr.GetClient(),
		Scheme:                mgr.GetScheme(),
		Storage:               storage,
		EventRecorder:         mgr.GetEventRecorderFor(controllerName),
		ExternalEventRecorder: eventRecorder,
		MetricsRecorder:       metricsH.MetricsRecorder,
	}).SetupWithManagerAndOptions(mgr, controllers.GitRepositoryReconcilerOptions{
		MaxConcurrentReconciles:   concurrent,
		DependencyRequeueInterval: requeueDependency,
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", sourcev1.GitRepositoryKind)
		os.Exit(1)
	}
	if err = (&controllers.HelmRepositoryReconciler{
		Client:                mgr.GetClient(),
		Scheme:                mgr.GetScheme(),
		Storage:               storage,
		Getters:               getters,
		EventRecorder:         mgr.GetEventRecorderFor(controllerName),
		ExternalEventRecorder: eventRecorder,
		MetricsRecorder:       metricsH.MetricsRecorder,
	}).SetupWithManagerAndOptions(mgr, controllers.HelmRepositoryReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", sourcev1.HelmRepositoryKind)
		os.Exit(1)
	}
	if err = (&controllers.HelmChartReconciler{
		Client:                mgr.GetClient(),
		Scheme:                mgr.GetScheme(),
		Storage:               storage,
		Getters:               getters,
		EventRecorder:         mgr.GetEventRecorderFor(controllerName),
		ExternalEventRecorder: eventRecorder,
		MetricsRecorder:       metricsH.MetricsRecorder,
	}).SetupWithManagerAndOptions(mgr, controllers.HelmChartReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", sourcev1.HelmChartKind)
		os.Exit(1)
	}
	if err = (&controllers.BucketReconciler{
		Client:  mgr.GetClient(),
		Events:  eventsH,
		Metrics: metricsH,
		Storage: storage,
	}).SetupWithManagerAndOptions(mgr, controllers.BucketReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
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

func mustInitStorage(path string, storageAdvAddr string, l logr.Logger) *controllers.Storage {
	if path == "" {
		p, _ := os.Getwd()
		path = filepath.Join(p, "bin")
		os.MkdirAll(path, 0777)
	}

	storage, err := controllers.NewStorage(path, storageAdvAddr, 5*time.Minute)
	if err != nil {
		l.Error(err, "unable to initialise storage")
		os.Exit(1)
	}

	return storage
}

func determineAdvStorageAddr(storageAddr string, l logr.Logger) string {
	// TODO(hidde): remove next MINOR prerelease as it can be passed in using
	//  Kubernetes' substitution.
	if os.Getenv("RUNTIME_NAMESPACE") != "" {
		svcParts := strings.Split(os.Getenv("HOSTNAME"), "-")
		return fmt.Sprintf("%s.%s",
			strings.Join(svcParts[:len(svcParts)-2], "-"), os.Getenv("RUNTIME_NAMESPACE"))
	}

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
