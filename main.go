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
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

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
	var metricsAddr string
	var enableLeaderElection bool
	var storagePath string
	var storageAddr string
	flag.StringVar(&metricsAddr, "metrics-addr", ":9090", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&storagePath, "storage-path", "", "The local storage path.")
	flag.StringVar(&storageAddr, "storage-addr", ":8080", "The address the static file server binds to.")

	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "305740c0.fluxcd.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	storage := mustInitStorage(storagePath, setupLog)

	go startFileServer(storage.BasePath, storageAddr, setupLog)

	if err = (&controllers.GitRepositoryReconciler{
		Client:  mgr.GetClient(),
		Log:     ctrl.Log.WithName("controllers").WithName("GitRepository"),
		Scheme:  mgr.GetScheme(),
		Kind:    "gitrepository",
		Storage: storage,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "GitRepository")
		os.Exit(1)
	}
	if err = (&controllers.HelmRepositoryReconciler{
		Client:  mgr.GetClient(),
		Log:     ctrl.Log.WithName("controllers").WithName("HelmRepository"),
		Scheme:  mgr.GetScheme(),
		Kind:    "helmrepository",
		Storage: storage,
		Getters: getters,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "HelmRepository")
		os.Exit(1)
	}
	if err = (&controllers.HelmChartReconciler{
		Client:  mgr.GetClient(),
		Log:     ctrl.Log.WithName("controllers").WithName("HelmChart"),
		Scheme:  mgr.GetScheme(),
		Kind:    "helmchart",
		Storage: storage,
		Getters: getters,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "HelmChart")
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

func mustInitStorage(path string, l logr.Logger) *controllers.Storage {
	if path == "" {
		p, _ := os.Getwd()
		path = filepath.Join(p, "bin")
	}

	hostname := "localhost"
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
