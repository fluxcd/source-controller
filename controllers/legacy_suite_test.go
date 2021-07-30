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

package controllers

import (
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/getter"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var k8sManager ctrl.Manager
var ginkgoTestEnv *envtest.Environment
var ginkgoTestStorage *Storage

var examplePublicKey []byte
var examplePrivateKey []byte
var exampleCA []byte

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func(done Done) {
	logf.SetLogger(
		zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)),
	)

	By("bootstrapping test environment")
	t := true
	if os.Getenv("TEST_USE_EXISTING_CLUSTER") == "true" {
		ginkgoTestEnv = &envtest.Environment{
			UseExistingCluster: &t,
		}
	} else {
		ginkgoTestEnv = &envtest.Environment{
			CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
		}
	}

	var err error
	cfg, err = ginkgoTestEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	err = sourcev1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = sourcev1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = sourcev1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	Expect(loadExampleKeys()).To(Succeed())

	tmpStoragePath, err := os.MkdirTemp("", "source-controller-storage-")
	Expect(err).NotTo(HaveOccurred(), "failed to create tmp storage dir")

	ginkgoTestStorage, err = NewStorage(tmpStoragePath, "localhost:5050", time.Second*30)
	Expect(err).NotTo(HaveOccurred(), "failed to create tmp storage")
	// serve artifacts from the filesystem, as done in main.go
	fs := http.FileServer(http.Dir(tmpStoragePath))
	http.Handle("/", fs)
	go http.ListenAndServe(":5050", nil)

	k8sManager, err = ctrl.NewManager(cfg, ctrl.Options{
		MetricsBindAddress: "0",
		Scheme:             scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	err = (&GitRepositoryReconciler{
		Client:  k8sManager.GetClient(),
		Scheme:  scheme.Scheme,
		Storage: ginkgoTestStorage,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred(), "failed to setup GtRepositoryReconciler")

	err = (&HelmRepositoryReconciler{
		Client:  k8sManager.GetClient(),
		Scheme:  scheme.Scheme,
		Storage: ginkgoTestStorage,
		Getters: getter.Providers{getter.Provider{
			Schemes: []string{"http", "https"},
			New:     getter.NewHTTPGetter,
		}},
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred(), "failed to setup HelmRepositoryReconciler")

	err = (&HelmChartReconciler{
		Client:  k8sManager.GetClient(),
		Scheme:  scheme.Scheme,
		Storage: ginkgoTestStorage,
		Getters: getter.Providers{getter.Provider{
			Schemes: []string{"http", "https"},
			New:     getter.NewHTTPGetter,
		}},
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred(), "failed to setup HelmChartReconciler")

	go func() {
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred())
	}()

	k8sClient = k8sManager.GetClient()
	Expect(k8sClient).ToNot(BeNil())

	close(done)
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	if ginkgoTestStorage != nil {
		err := os.RemoveAll(ginkgoTestStorage.BasePath)
		Expect(err).NotTo(HaveOccurred())
	}
	err := ginkgoTestEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})

func init() {
	rand.Seed(time.Now().UnixNano())
}

func loadExampleKeys() (err error) {
	examplePublicKey, err = os.ReadFile("testdata/certs/server.pem")
	if err != nil {
		return err
	}
	examplePrivateKey, err = os.ReadFile("testdata/certs/server-key.pem")
	if err != nil {
		return err
	}
	exampleCA, err = os.ReadFile("testdata/certs/ca.pem")
	return err
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz1234567890")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
