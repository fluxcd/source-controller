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
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"helm.sh/helm/v3/pkg/getter"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	crtlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/logger"
	"github.com/fluxcd/pkg/runtime/metrics"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/controllers"
	// +kubebuilder:scaffold:imports
)

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
	_ = clientgoscheme.AddToScheme(scheme)

	_ = sourcev1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var (
		metricsAddr          string
		eventsAddr           string
		enableLeaderElection bool
		storagePath          string
		storageAddr          string
		storageAdvAddr       string
		concurrent           int
		logLevel             string
		logJSON              bool
		watchAllNamespaces   bool
	)

	flag.StringVar(&metricsAddr, "metrics-addr", envOrDefault("METRICS_ADDR", ":8080"),
		"The address the metric endpoint binds to.")
	flag.StringVar(&eventsAddr, "events-addr", envOrDefault("EVENTS_ADDR", ""),
		"The address of the events receiver.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&storagePath, "storage-path", envOrDefault("STORAGE_PATH", ""),
		"The local storage path.")
	flag.StringVar(&storageAddr, "storage-addr", envOrDefault("STORAGE_ADDR", ":9090"),
		"The address the static file server binds to.")
	flag.StringVar(&storageAdvAddr, "storage-adv-addr", envOrDefault("STORAGE_ADV_ADDR", ""),
		"The advertised address of the static file server.")
	flag.IntVar(&concurrent, "concurrent", 2, "The number of concurrent reconciles per controller.")
	flag.StringVar(&logLevel, "log-level", "info", "Set logging level. Can be debug, info or error.")
	flag.BoolVar(&logJSON, "log-json", false, "Set logging to JSON format.")
	flag.BoolVar(&watchAllNamespaces, "watch-all-namespaces", true,
		"Watch for custom resources in all namespaces, if set to false it will only watch the runtime namespace.")
	flag.Parse()

	ctrl.SetLogger(logger.NewLogger(logLevel, logJSON))

	var eventRecorder *events.Recorder
	if eventsAddr != "" {
		if er, err := events.NewRecorder(eventsAddr, "source-controller"); err != nil {
			setupLog.Error(err, "unable to create event recorder")
			os.Exit(1)
		} else {
			eventRecorder = er
		}
	}

	metricsRecorder := metrics.NewRecorder()
	crtlmetrics.Registry.MustRegister(metricsRecorder.Collectors()...)

	watchNamespace := ""
	if !watchAllNamespaces {
		watchNamespace = os.Getenv("RUNTIME_NAMESPACE")
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "305740c0.fluxcd.io",
		Namespace:          watchNamespace,
		Logger:             ctrl.Log,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if storageAdvAddr == "" {
		storageAdvAddr = determineAdvStorageAddr(storageAddr, setupLog)
	}
	storage := mustInitStorage(storagePath, storageAdvAddr, setupLog)
	go startFileServer(storage.BasePath, storageAddr, setupLog)

	if err = (&controllers.GitRepositoryReconciler{
		Client:                mgr.GetClient(),
		Log:                   ctrl.Log.WithName("controllers").WithName(sourcev1.GitRepositoryKind),
		Scheme:                mgr.GetScheme(),
		Storage:               storage,
		EventRecorder:         mgr.GetEventRecorderFor("source-controller"),
		ExternalEventRecorder: eventRecorder,
		MetricsRecorder:       metricsRecorder,
	}).SetupWithManagerAndOptions(mgr, controllers.GitRepositoryReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", sourcev1.GitRepositoryKind)
		os.Exit(1)
	}
	if err = (&controllers.HelmRepositoryReconciler{
		Client:                mgr.GetClient(),
		Log:                   ctrl.Log.WithName("controllers").WithName(sourcev1.HelmRepositoryKind),
		Scheme:                mgr.GetScheme(),
		Storage:               storage,
		Getters:               getters,
		EventRecorder:         mgr.GetEventRecorderFor("source-controller"),
		ExternalEventRecorder: eventRecorder,
		MetricsRecorder:       metricsRecorder,
	}).SetupWithManagerAndOptions(mgr, controllers.HelmRepositoryReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", sourcev1.HelmRepositoryKind)
		os.Exit(1)
	}
	if err = (&controllers.HelmChartReconciler{
		Client:                mgr.GetClient(),
		Log:                   ctrl.Log.WithName("controllers").WithName(sourcev1.HelmChartKind),
		Scheme:                mgr.GetScheme(),
		Storage:               storage,
		Getters:               getters,
		EventRecorder:         mgr.GetEventRecorderFor("source-controller"),
		ExternalEventRecorder: eventRecorder,
		MetricsRecorder:       metricsRecorder,
	}).SetupWithManagerAndOptions(mgr, controllers.HelmChartReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", sourcev1.HelmChartKind)
		os.Exit(1)
	}
	if err = (&controllers.BucketReconciler{
		Client:                mgr.GetClient(),
		Log:                   ctrl.Log.WithName("controllers").WithName("Bucket"),
		Scheme:                mgr.GetScheme(),
		Storage:               storage,
		EventRecorder:         mgr.GetEventRecorderFor("source-controller"),
		ExternalEventRecorder: eventRecorder,
		MetricsRecorder:       metricsRecorder,
	}).SetupWithManagerAndOptions(mgr, controllers.BucketReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Bucket")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func startFileServer(path string, address string, l logr.Logger) {
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
