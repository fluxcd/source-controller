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
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/testenv"
	"github.com/fluxcd/pkg/testserver"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	// +kubebuilder:scaffold:imports
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
	testEnv      *testenv.Environment
	testStorage  *Storage
	testServer   *testserver.ArtifactServer
	testEventsH  controller.Events
	testMetricsH controller.Metrics
	ctx          = ctrl.SetupSignalHandler()
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

	testEnv = testenv.New(testenv.WithCRDPath(filepath.Join("..", "config", "crd", "bases")))

	var err error
	testServer, err = testserver.NewTempArtifactServer()
	if err != nil {
		panic(fmt.Sprintf("Failed to create a temporary storage server: %v", err))
	}
	fmt.Println("Starting the test storage server")
	testServer.Start()

	testStorage, err = newTestStorage(testServer.HTTPServer)
	if err != nil {
		panic(fmt.Sprintf("Failed to create a test storage: %v", err))
	}

	testEventsH = controller.MakeEvents(testEnv, "source-controller-test", nil)
	testMetricsH = controller.MustMakeMetrics(testEnv)

	//if err := (&GitRepositoryReconciler{
	//	Client:  testEnv,
	//	Events:  testEventsH,
	//	Metrics: testMetricsH,
	//	Storage: testStorage,
	//}).SetupWithManager(testEnv); err != nil {
	//	panic(fmt.Sprintf("Failed to start GitRepositoryReconciler: %v", err))
	//}

	go func() {
		fmt.Println("Starting the test environment")
		if err := testEnv.Start(ctx); err != nil {
			panic(fmt.Sprintf("Failed to start the test environment manager: %v", err))
		}
	}()
	<-testEnv.Manager.Elected()

	code := m.Run()

	fmt.Println("Stopping the test environment")
	if err := testEnv.Stop(); err != nil {
		panic(fmt.Sprintf("Failed to stop the test environment: %v", err))
	}

	fmt.Println("Stopping the storage server")
	testServer.Stop()
	if err := os.RemoveAll(testServer.Root()); err != nil {
		panic(fmt.Sprintf("Failed to remove storage server dir: %v", err))
	}

	os.Exit(code)
}

func initTestTLS() {
	var err error
	tlsPublicKey, err = os.ReadFile("testdata/certs/server.pem")
	if err != nil {
		panic(err)
	}
	tlsPrivateKey, err = os.ReadFile("testdata/certs/server-key.pem")
	if err != nil {
		panic(err)
	}
	tlsCA, err = os.ReadFile("testdata/certs/ca.pem")
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
