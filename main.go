/*
Copyright 2020 The Flux CD contributors.

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
	uzap "go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"helm.sh/helm/v3/pkg/getter"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/fluxcd/pkg/recorder"
	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
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
		concurrent           int
		logLevel             string
		logJSON              bool
	)

	flag.StringVar(&metricsAddr, "metrics-addr", envOrDefault("METRICS_ADDR", ":8080"), "The address the metric endpoint binds to.")
	flag.StringVar(&eventsAddr, "events-addr", envOrDefault("EVENTS_ADDR", ""), "The address of the events receiver.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&storagePath, "storage-path", envOrDefault("STORAGE_PATH", ""), "The local storage path.")
	flag.StringVar(&storageAddr, "storage-addr", envOrDefault("STORAGE_ADDR", ":9090"), "The address the static file server binds to.")
	flag.IntVar(&concurrent, "concurrent", 2, "The number of concurrent reconciles per controller.")
	flag.StringVar(&logLevel, "log-level", "info", "Set logging level. Can be debug, info or error.")
	flag.BoolVar(&logJSON, "log-json", false, "Set logging to JSON format.")

	flag.Parse()

	ctrl.SetLogger(newLogger(logLevel, logJSON))

	var eventRecorder *recorder.EventRecorder
	if eventsAddr != "" {
		if er, err := recorder.NewEventRecorder(eventsAddr, "source-controller"); err != nil {
			setupLog.Error(err, "unable to create event recorder")
			os.Exit(1)
		} else {
			eventRecorder = er
		}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "305740c0.fluxcd.io",
		Namespace:          os.Getenv("RUNTIME_NAMESPACE"),
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	storage := mustInitStorage(storagePath, storageAddr, setupLog)

	go startFileServer(storage.BasePath, storageAddr, setupLog)

	if err = (&controllers.GitRepositoryReconciler{
		Client:                mgr.GetClient(),
		Log:                   ctrl.Log.WithName("controllers").WithName(sourcev1.GitRepositoryKind),
		Scheme:                mgr.GetScheme(),
		Storage:               storage,
		EventRecorder:         mgr.GetEventRecorderFor("source-controller"),
		ExternalEventRecorder: eventRecorder,
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
	}).SetupWithManagerAndOptions(mgr, controllers.HelmChartReconcilerOptions{
		MaxConcurrentReconciles: concurrent,
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", sourcev1.HelmChartKind)
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// newLogger returns a logger configured for dev or production use.
// For production the log format is JSON, the timestamps format is ISO8601
// and stack traces are logged when the level is set to debug.
func newLogger(level string, production bool) logr.Logger {
	if !production {
		return zap.New(zap.UseDevMode(true))
	}

	encCfg := uzap.NewProductionEncoderConfig()
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder := zap.Encoder(zapcore.NewJSONEncoder(encCfg))

	logLevel := zap.Level(zapcore.InfoLevel)
	stacktraceLevel := zap.StacktraceLevel(zapcore.PanicLevel)

	switch level {
	case "debug":
		logLevel = zap.Level(zapcore.DebugLevel)
		stacktraceLevel = zap.StacktraceLevel(zapcore.ErrorLevel)
	case "error":
		logLevel = zap.Level(zapcore.ErrorLevel)
	}

	return zap.New(encoder, logLevel, stacktraceLevel)
}

func startFileServer(path string, address string, l logr.Logger) {
	fs := http.FileServer(http.Dir(path))
	http.Handle("/", fs)
	err := http.ListenAndServe(address, nil)
	if err != nil {
		l.Error(err, "file server error")
	}
}

func mustInitStorage(path string, storageAddr string, l logr.Logger) *controllers.Storage {
	if path == "" {
		p, _ := os.Getwd()
		path = filepath.Join(p, "bin")
		os.MkdirAll(path, 0777)
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

	hostname := net.JoinHostPort(host, port)

	if os.Getenv("RUNTIME_NAMESPACE") != "" {
		svcParts := strings.Split(os.Getenv("HOSTNAME"), "-")
		hostname = fmt.Sprintf("%s.%s",
			strings.Join(svcParts[:len(svcParts)-2], "-"), os.Getenv("RUNTIME_NAMESPACE"))
	}

	storage, err := controllers.NewStorage(path, hostname, 5*time.Minute)
	if err != nil {
		l.Error(err, "unable to initialise storage")
		os.Exit(1)
	}

	return storage
}

func envOrDefault(envName, dflt string) string {
	ret := os.Getenv(envName)
	if ret != "" {
		return ret
	}

	return dflt
}
