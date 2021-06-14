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
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/testserver"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	// +kubebuilder:scaffold:imports
	"github.com/fluxcd/source-controller/internal/testenv"
)

// These tests make use of plain Go using Gomega for assertions.
// At the beginning of every (sub)test Gomega can be initialized
// using gomega.NewWithT.
// Refer to http://onsi.github.io/gomega/ to learn more about
// Gomega.

const (
	timeout  = 10 * time.Second
	interval = 1 * time.Second
)

var (
	env      *testenv.Environment
	storage  *Storage
	server   *testserver.ArtifactServer
	eventsH  controller.Events
	metricsH controller.Metrics
	ctx      = ctrl.SetupSignalHandler()
)

var (
	tlsPublicKey  []byte
	tlsPrivateKey []byte
	tlsCA         []byte
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestMain(m *testing.M) {
	initTestTLS()

	utilruntime.Must(sourcev1.AddToScheme(scheme.Scheme))

	env = testenv.New(testenv.WithCRDPath(filepath.Join("..", "config", "crd", "bases")))

	var err error
	server, err = testserver.NewTempArtifactServer()
	if err != nil {
		panic(fmt.Sprintf("Failed to create a temporary storage server: %v", err))
	}
	fmt.Println("Starting the test storage server")
	server.Start()

	storage, err = newTestStorage(server.HTTPServer)
	if err != nil {
		panic(fmt.Sprintf("Failed to create a test storage: %v", err))
	}

	eventsH = controller.MakeEvents(env, "test", nil)
	metricsH = controller.MustMakeMetrics(env)

	if err := (&GitRepositoryReconciler{
		Client:  env,
		Events:  eventsH,
		Metrics: metricsH,
		Storage: storage,
	}).SetupWithManager(env); err != nil {
		panic(fmt.Sprintf("Failed to start GitRepositoryReconciler: %v", err))
	}

	if err := (&HelmRepositoryReconciler{
		Client:  env,
		Events:  eventsH,
		Metrics: metricsH,
		Getters: testGetters,
		Storage: storage,
	}).SetupWithManager(env); err != nil {
		panic(fmt.Sprintf("Failed to start HelmRepositoryReconciler: %v", err))
	}

	if err := (&BucketReconciler{
		Client:  env,
		Events:  eventsH,
		Metrics: metricsH,
		Storage: storage,
	}).SetupWithManager(env); err != nil {
		panic(fmt.Sprintf("Failed to start BucketReconciler: %v", err))
	}

	if err := (&HelmChartReconciler{
		Client:  env,
		Events:  eventsH,
		Metrics: metricsH,
		Getters: testGetters,
		Storage: storage,
	}).SetupWithManager(env); err != nil {
		panic(fmt.Sprintf("Failed to start HelmChartReconciler: %v", err))
	}

	go func() {
		fmt.Println("Starting the test environment")
		if err := env.Start(ctx); err != nil {
			panic(fmt.Sprintf("Failed to start the test environment manager: %v", err))
		}
	}()
	<-env.Manager.Elected()

	code := m.Run()

	fmt.Println("Stopping the test environment")
	if err := env.Stop(); err != nil {
		panic(fmt.Sprintf("Failed to stop the test environment: %v", err))
	}

	fmt.Println("Stopping the storage server")
	server.Stop()
	if err := os.RemoveAll(server.Root()); err != nil {
		panic(fmt.Sprintf("Failed to remove storage server dir: %v", err))
	}

	os.Exit(code)
}

func initTestTLS() {
	var err error
	tlsPublicKey, err = ioutil.ReadFile("testdata/certs/server.pem")
	if err != nil {
		panic(err)
	}
	tlsPrivateKey, err = ioutil.ReadFile("testdata/certs/server-key.pem")
	if err != nil {
		panic(err)
	}
	tlsCA, err = ioutil.ReadFile("testdata/certs/ca.pem")
	if err != nil {
		panic(err)
	}
}

func newTestStorage(s *testserver.HTTPServer) (*Storage, error) {
	storage, err := NewStorage(s.Root(), s.URL(), timeout)
	if err != nil {
		return nil, err
	}
	return storage, nil
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz1234567890")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
