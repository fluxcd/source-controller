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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/configuration"
	dockerRegistry "github.com/distribution/distribution/v3/registry"
	_ "github.com/distribution/distribution/v3/registry/auth/htpasswd"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/foxcpp/go-mockdns"
	"github.com/phayes/freeport"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"helm.sh/helm/v3/pkg/getter"
	helmreg "helm.sh/helm/v3/pkg/registry"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/artifact/config"
	"github.com/fluxcd/pkg/artifact/digest"
	"github.com/fluxcd/pkg/artifact/storage"
	"github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/testenv"
	"github.com/fluxcd/pkg/testserver"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
	"github.com/werf/nelm-source-controller/internal/cache"
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
	k8sClient    client.Client
	testEnv      *testenv.Environment
	testStorage  *storage.Storage
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
	tlsPublicKey     []byte
	tlsPrivateKey    []byte
	tlsCA            []byte
	clientPublicKey  []byte
	clientPrivateKey []byte
)

var (
	testRegistryServer *registryClientTestServer
	testCache          *cache.Cache
)

type registryClientTestServer struct {
	out            io.Writer
	registryHost   string
	workspaceDir   string
	registryClient *helmreg.Client
	dnsServer      *mockdns.Server
}

type registryOptions struct {
	withBasicAuth      bool
	withTLS            bool
	withClientCertAuth bool
}

func setupRegistryServer(ctx context.Context, workspaceDir string, opts registryOptions) (*registryClientTestServer, error) {
	server := &registryClientTestServer{}

	if workspaceDir == "" {
		return nil, fmt.Errorf("workspace directory cannot be an empty string")
	}

	server.workspaceDir = workspaceDir

	var out bytes.Buffer
	server.out = &out

	// init test client options
	clientOpts := []helmreg.ClientOption{
		helmreg.ClientOptDebug(true),
		helmreg.ClientOptWriter(server.out),
	}

	config := &configuration.Configuration{}
	port, err := freeport.GetFreePort()
	if err != nil {
		return nil, fmt.Errorf("failed to get free port: %s", err)
	}

	// Change the registry host to a host which is not localhost and
	// mock DNS to map example.com to 127.0.0.1.
	// This is required because Docker enforces HTTP if the registry
	// is hosted on localhost/127.0.0.1.
	if opts.withTLS {
		server.registryHost = fmt.Sprintf("example.com:%d", port)
		// Disable DNS server logging as it is extremely chatty.
		dnsLog := log.Default()
		dnsLog.SetOutput(io.Discard)
		server.dnsServer, err = mockdns.NewServerWithLogger(map[string]mockdns.Zone{
			"example.com.": {
				A: []string{"127.0.0.1"},
			},
		}, dnsLog, false)
		if err != nil {
			return nil, err
		}
		server.dnsServer.PatchNet(net.DefaultResolver)
	} else {
		server.registryHost = fmt.Sprintf("127.0.0.1:%d", port)
	}

	config.HTTP.Addr = fmt.Sprintf(":%d", port)
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
		// Configure CA certificates only if client cert authentication is enabled.
		if opts.withClientCertAuth {
			config.HTTP.TLS.ClientCAs = []string{"testdata/certs/ca.pem"}
		}

		// add TLS configured HTTP client option to clientOpts
		httpClient, err := tlsConfiguredHTTPCLient()
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS configured HTTP client: %s", err)
		}
		clientOpts = append(clientOpts, helmreg.ClientOptHTTPClient(httpClient))
	} else {
		clientOpts = append(clientOpts, helmreg.ClientOptPlainHTTP())
	}

	// setup logger options
	config.Log.AccessLog.Disabled = true
	config.Log.Level = "error"
	logrus.SetOutput(io.Discard)

	registry, err := dockerRegistry.NewRegistry(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker registry: %w", err)
	}

	// init test client
	helmClient, err := helmreg.NewClient(clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry client: %s", err)
	}
	server.registryClient = helmClient

	// Start Docker registry
	go registry.ListenAndServe()

	return server, nil
}

func tlsConfiguredHTTPCLient() (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(tlsCA) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}
	cert, err := tls.LoadX509KeyPair("testdata/certs/server.pem", "testdata/certs/server-key.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %s", err)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
				Certificates: []tls.Certificate{
					cert,
				},
			},
		},
	}
	return httpClient, nil
}

func (r *registryClientTestServer) Close() {
	if r.dnsServer != nil {
		mockdns.UnpatchNet(net.DefaultResolver)
		r.dnsServer.Close()
	}
}

func TestMain(m *testing.M) {
	initTestTLS()

	utilruntime.Must(sourcev1.AddToScheme(scheme.Scheme))

	testEnv = testenv.New(
		testenv.WithCRDPath(filepath.Join("..", "..", "config", "crd", "bases")),
		testenv.WithMaxConcurrentReconciles(4),
	)

	var err error
	// Initialize a cacheless client for tests that need the latest objects.
	k8sClient, err = client.New(testEnv.Config, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		panic(fmt.Sprintf("failed to create k8s client: %v", err))
	}

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

	testMetricsH = controller.NewMetrics(testEnv, metrics.MustMakeRecorder(), sourcev1.SourceFinalizer)

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
	defer testRegistryServer.Close()

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
	clientPrivateKey, err = os.ReadFile("testdata/certs/client-key.pem")
	if err != nil {
		panic(err)
	}
	clientPublicKey, err = os.ReadFile("testdata/certs/client.pem")
	if err != nil {
		panic(err)
	}
}

func newTestStorage(s *testserver.HTTPServer) (*storage.Storage, error) {
	opts := &config.Options{
		StoragePath:              s.Root(),
		StorageAddress:           s.URL(),
		StorageAdvAddress:        s.URL(),
		ArtifactRetentionTTL:     retentionTTL,
		ArtifactRetentionRecords: retentionRecords,
		ArtifactDigestAlgo:       digest.Canonical.String(),
	}
	st, err := storage.New(opts)
	if err != nil {
		return nil, err
	}
	return st, nil
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

func logOCIRepoStatus(t *testing.T, obj *sourcev1.OCIRepository) {
	sts, _ := yaml.Marshal(obj.Status)
	t.Log(string(sts))
}
