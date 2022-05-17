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
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/registry"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/testenv"
	"github.com/fluxcd/pkg/testserver"
	"github.com/phayes/freeport"

	"github.com/distribution/distribution/v3/configuration"
	dockerRegistry "github.com/distribution/distribution/v3/registry"
	_ "github.com/distribution/distribution/v3/registry/auth/htpasswd"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/internal/cache"
	"github.com/fluxcd/source-controller/internal/helm/util"
	// +kubebuilder:scaffold:imports
)

// These tests make use of plain Go using Gomega for assertions.
// At the beginning of every (sub)test Gomega can be initialized
// using gomega.NewWithT.
// Refer to http://onsi.github.io/gomega/ to learn more about
// Gomega.

const (
	timeout          = 10 * time.Second
	interval         = 1 * time.Second
	retentionTTL     = 2 * time.Second
	retentionRecords = 2
)

var (
	testEnv      *testenv.Environment
	testStorage  *Storage
	testServer   *testserver.ArtifactServer
	testMetricsH controller.Metrics
	ctx          = ctrl.SetupSignalHandler()
)

var (
	testGetters = getter.Providers{
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

var (
	tlsPublicKey  []byte
	tlsPrivateKey []byte
	tlsCA         []byte
)

var (
	testRegistryClient *registry.Client
	testRegistryserver *RegistryClientTestServer
)

var (
	testWorkspaceDir         = "registry-test"
	testHtpasswdFileBasename = "authtest.htpasswd"
	testUsername             = "myuser"
	testPassword             = "mypass"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type RegistryClientTestServer struct {
	Out                io.Writer
	DockerRegistryHost string
	WorkspaceDir       string
	RegistryClient     *registry.Client
}

func SetupServer(server *RegistryClientTestServer) string {
	// Create a temporary workspace directory for the registry
	server.WorkspaceDir = testWorkspaceDir
	os.RemoveAll(server.WorkspaceDir)
	err := os.Mkdir(server.WorkspaceDir, 0700)
	if err != nil {
		panic(fmt.Sprintf("failed to create workspace directory: %s", err))
	}

	var out bytes.Buffer
	server.Out = &out

	// init test client
	server.RegistryClient, err = registry.NewClient(
		registry.ClientOptDebug(true),
		registry.ClientOptWriter(server.Out),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create registry client: %s", err))
	}

	// create htpasswd file (w BCrypt, which is required)
	pwBytes, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("failed to generate password: %s", err))
	}

	htpasswdPath := filepath.Join(testWorkspaceDir, testHtpasswdFileBasename)
	err = ioutil.WriteFile(htpasswdPath, []byte(fmt.Sprintf("%s:%s\n", testUsername, string(pwBytes))), 0644)
	if err != nil {
		panic(fmt.Sprintf("failed to create htpasswd file: %s", err))
	}

	// Registry config
	config := &configuration.Configuration{}
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(fmt.Sprintf("failed to get free port: %s", err))
	}

	server.DockerRegistryHost = fmt.Sprintf("localhost:%d", port)
	config.HTTP.Addr = fmt.Sprintf("127.0.0.1:%d", port)
	config.HTTP.DrainTimeout = time.Duration(10) * time.Second
	config.Storage = map[string]configuration.Parameters{"inmemory": map[string]interface{}{}}
	config.Auth = configuration.Auth{
		"htpasswd": configuration.Parameters{
			"realm": "localhost",
			"path":  htpasswdPath,
		},
	}
	dockerRegistry, err := dockerRegistry.NewRegistry(context.Background(), config)
	if err != nil {
		panic(fmt.Sprintf("failed to create docker registry: %s", err))
	}

	// Start Docker registry
	go dockerRegistry.ListenAndServe()

	return server.WorkspaceDir
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

	testMetricsH = controller.MustMakeMetrics(testEnv)

	testRegistryserver = &RegistryClientTestServer{}
	registryWorkspaceDir := SetupServer(testRegistryserver)

	testRegistryClient, err = registry.NewClient(registry.ClientOptWriter(os.Stdout))
	if err != nil {
		panic(fmt.Sprintf("Failed to create OCI registry client"))
	}

	if err := (&GitRepositoryReconciler{
		Client:        testEnv,
		EventRecorder: record.NewFakeRecorder(32),
		Metrics:       testMetricsH,
		Storage:       testStorage,
	}).SetupWithManager(testEnv); err != nil {
		panic(fmt.Sprintf("Failed to start GitRepositoryReconciler: %v", err))
	}

	if err := (&BucketReconciler{
		Client:        testEnv,
		EventRecorder: record.NewFakeRecorder(32),
		Metrics:       testMetricsH,
		Storage:       testStorage,
	}).SetupWithManager(testEnv); err != nil {
		panic(fmt.Sprintf("Failed to start BucketReconciler: %v", err))
	}

	if err := (&HelmRepositoryReconciler{
		Client:        testEnv,
		EventRecorder: record.NewFakeRecorder(32),
		Metrics:       testMetricsH,
		Getters:       testGetters,
		Storage:       testStorage,
	}).SetupWithManager(testEnv); err != nil {
		panic(fmt.Sprintf("Failed to start HelmRepositoryReconciler: %v", err))
	}

	if err = (&HelmRepositoryOCIReconciler{
		Client:                  testEnv,
		EventRecorder:           record.NewFakeRecorder(32),
		Metrics:                 testMetricsH,
		Getters:                 testGetters,
		RegistryClientGenerator: util.RegistryClientGenerator,
	}).SetupWithManager(testEnv); err != nil {
		panic(fmt.Sprintf("Failed to start HelmRepositoryOCIReconciler: %v", err))
	}

	c := cache.New(5, 1*time.Second)
	cacheRecorder := cache.MustMakeMetrics()
	if err := (&HelmChartReconciler{
		Client:        testEnv,
		EventRecorder: record.NewFakeRecorder(32),
		Metrics:       testMetricsH,
		Getters:       testGetters,
		Storage:       testStorage,
		Cache:         c,
		TTL:           1 * time.Second,
		CacheRecorder: cacheRecorder,
	}).SetupWithManager(testEnv); err != nil {
		panic(fmt.Sprintf("Failed to start HelmRepositoryReconciler: %v", err))
	}

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

	if err := os.RemoveAll(registryWorkspaceDir); err != nil {
		panic(fmt.Sprintf("Failed to remove registry workspace dir: %v", err))
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
	storage, err := NewStorage(s.Root(), s.URL(), retentionTTL, retentionRecords)
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

func int64p(i int64) *int64 {
	return &i
}
