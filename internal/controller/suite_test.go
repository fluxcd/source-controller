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

package controller

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phayes/freeport"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"helm.sh/helm/v3/pkg/getter"
	helmreg "helm.sh/helm/v3/pkg/registry"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/distribution/distribution/v3/configuration"
	dcontext "github.com/distribution/distribution/v3/context"
	dockerRegistry "github.com/distribution/distribution/v3/registry"
	_ "github.com/distribution/distribution/v3/registry/auth/htpasswd"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"

	"github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/testenv"
	"github.com/fluxcd/pkg/testserver"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	sourcev1beta2 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/internal/cache"
	"github.com/fluxcd/source-controller/internal/helm/registry"
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

const (
	testRegistryHtpasswdFileBasename = "authtest.htpasswd"
	testRegistryUsername             = "myuser"
	testRegistryPassword             = "mypass"
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
	testRegistryServer *registryClientTestServer
	testCache          *cache.Cache
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type registryClientTestServer struct {
	out            io.Writer
	registryHost   string
	workspaceDir   string
	registryClient *helmreg.Client
}

type registryOptions struct {
	withBasicAuth bool
	withTLS       bool
}

func setupRegistryServer(ctx context.Context, workspaceDir string, opts registryOptions) (*registryClientTestServer, error) {
	server := &registryClientTestServer{}

	if workspaceDir == "" {
		return nil, fmt.Errorf("workspace directory cannot be an empty string")
	}

	server.workspaceDir = workspaceDir

	var out bytes.Buffer
	server.out = &out

	// init test client
	client, err := helmreg.NewClient(
		helmreg.ClientOptDebug(true),
		helmreg.ClientOptWriter(server.out),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry client: %s", err)
	}
	server.registryClient = client

	config := &configuration.Configuration{}
	port, err := freeport.GetFreePort()
	if err != nil {
		return nil, fmt.Errorf("failed to get free port: %s", err)
	}

	server.registryHost = fmt.Sprintf("localhost:%d", port)
	config.HTTP.Addr = fmt.Sprintf("127.0.0.1:%d", port)
	config.HTTP.DrainTimeout = time.Duration(10) * time.Second
	config.Storage = map[string]configuration.Parameters{"inmemory": map[string]interface{}{}}

	if opts.withBasicAuth {
		// create htpasswd file (w BCrypt, which is required)
		pwBytes, err := bcrypt.GenerateFromPassword([]byte(testRegistryPassword), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to generate password: %s", err)
		}

		htpasswdPath := filepath.Join(workspaceDir, testRegistryHtpasswdFileBasename)
		if err = os.WriteFile(htpasswdPath, []byte(fmt.Sprintf("%s:%s\n", testRegistryUsername, string(pwBytes))), 0644); err != nil {
			return nil, fmt.Errorf("failed to create htpasswd file: %s", err)
		}

		// Registry config
		config.Auth = configuration.Auth{
			"htpasswd": configuration.Parameters{
				"realm": "localhost",
				"path":  htpasswdPath,
			},
		}
	}

	if opts.withTLS {
		config.HTTP.TLS.Certificate = "testdata/certs/server.pem"
		config.HTTP.TLS.Key = "testdata/certs/server-key.pem"
	}

	// setup logger options
	config.Log.AccessLog.Disabled = true
	config.Log.Level = "error"
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	dcontext.SetDefaultLogger(logrus.NewEntry(logger))

	dockerRegistry, err := dockerRegistry.NewRegistry(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker registry: %w", err)
	}

	// Start Docker registry
	go dockerRegistry.ListenAndServe()

	return server, nil
}

func TestMain(m *testing.M) {
	initTestTLS()

	utilruntime.Must(sourcev1.AddToScheme(scheme.Scheme))
	utilruntime.Must(sourcev1beta2.AddToScheme(scheme.Scheme))

	testEnv = testenv.New(
		testenv.WithCRDPath(filepath.Join("..", "..", "config", "crd", "bases")),
		testenv.WithMaxConcurrentReconciles(4),
	)

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

	testWorkspaceDir, err := os.MkdirTemp("", "registry-test-")
	if err != nil {
		panic(fmt.Sprintf("failed to create workspace directory: %v", err))
	}
	testRegistryServer, err = setupRegistryServer(ctx, testWorkspaceDir, registryOptions{
		withBasicAuth: true,
	})
	if err != nil {
		panic(fmt.Sprintf("Failed to create a test registry server: %v", err))
	}

	if err := (&GitRepositoryReconciler{
		Client:        testEnv,
		EventRecorder: record.NewFakeRecorder(32),
		Metrics:       testMetricsH,
		Storage:       testStorage,
	}).SetupWithManagerAndOptions(testEnv, GitRepositoryReconcilerOptions{
		RateLimiter: controller.GetDefaultRateLimiter(),
	}); err != nil {
		panic(fmt.Sprintf("Failed to start GitRepositoryReconciler: %v", err))
	}

	if err := (&BucketReconciler{
		Client:        testEnv,
		EventRecorder: record.NewFakeRecorder(32),
		Metrics:       testMetricsH,
		Storage:       testStorage,
	}).SetupWithManagerAndOptions(testEnv, BucketReconcilerOptions{
		RateLimiter: controller.GetDefaultRateLimiter(),
	}); err != nil {
		panic(fmt.Sprintf("Failed to start BucketReconciler: %v", err))
	}

	testCache = cache.New(5, 1*time.Second)
	cacheRecorder := cache.MustMakeMetrics()

	if err := (&OCIRepositoryReconciler{
		Client:        testEnv,
		EventRecorder: record.NewFakeRecorder(32),
		Metrics:       testMetricsH,
		Storage:       testStorage,
	}).SetupWithManagerAndOptions(testEnv, OCIRepositoryReconcilerOptions{
		RateLimiter: controller.GetDefaultRateLimiter(),
	}); err != nil {
		panic(fmt.Sprintf("Failed to start OCIRepositoryReconciler: %v", err))
	}

	if err := (&HelmRepositoryReconciler{
		Client:        testEnv,
		EventRecorder: record.NewFakeRecorder(32),
		Metrics:       testMetricsH,
		Getters:       testGetters,
		Storage:       testStorage,
		Cache:         testCache,
		TTL:           1 * time.Second,
		CacheRecorder: cacheRecorder,
	}).SetupWithManagerAndOptions(testEnv, HelmRepositoryReconcilerOptions{
		RateLimiter: controller.GetDefaultRateLimiter(),
	}); err != nil {
		panic(fmt.Sprintf("Failed to start HelmRepositoryReconciler: %v", err))
	}

	if err = (&HelmRepositoryOCIReconciler{
		Client:                  testEnv,
		EventRecorder:           record.NewFakeRecorder(32),
		Metrics:                 testMetricsH,
		Getters:                 testGetters,
		RegistryClientGenerator: registry.ClientGenerator,
	}).SetupWithManagerAndOptions(testEnv, HelmRepositoryReconcilerOptions{
		RateLimiter: controller.GetDefaultRateLimiter(),
	}); err != nil {
		panic(fmt.Sprintf("Failed to start HelmRepositoryOCIReconciler: %v", err))
	}

	if err := (&HelmChartReconciler{
		Client:        testEnv,
		EventRecorder: record.NewFakeRecorder(32),
		Metrics:       testMetricsH,
		Getters:       testGetters,
		Storage:       testStorage,
		Cache:         testCache,
		TTL:           1 * time.Second,
		CacheRecorder: cacheRecorder,
	}).SetupWithManagerAndOptions(ctx, testEnv, HelmChartReconcilerOptions{
		RateLimiter: controller.GetDefaultRateLimiter(),
	}); err != nil {
		panic(fmt.Sprintf("Failed to start HelmChartReconciler: %v", err))
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

	if err := os.RemoveAll(testWorkspaceDir); err != nil {
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
