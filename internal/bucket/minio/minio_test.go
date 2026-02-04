/*
Copyright 2022 The Flux authors

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

package minio

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	miniov7 "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	. "github.com/onsi/gomega"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/sourceignore"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
	testlistener "github.com/werf/nelm-source-controller/tests/listener"
	testproxy "github.com/werf/nelm-source-controller/tests/proxy"
)

const (
	objectName string = "test.yaml"
	objectEtag string = "b07bba5a280b58791bc78fb9fc414b09"
)

var (
	// testMinioVersion is the version (image tag) of the Minio server image
	// used to test against.
	testMinioVersion = "RELEASE.2024-05-07T06-41-25Z"
	// testMinioRootUser is the root user of the Minio server.
	testMinioRootUser = "fluxcd"
	// testMinioRootPassword is the root password of the Minio server.
	testMinioRootPassword = "passw0rd!"
	// testVaultAddress is the address of the Minio server, it is set
	// by TestMain after booting it.
	testMinioAddress string
	// testMinioClient is the Minio client used to test against, it is set
	// by TestMain after booting the Minio server.
	testMinioClient *MinioClient
	// testTLSConfig is the TLS configuration used to connect to the Minio server.
	testTLSConfig *tls.Config
	// testServerCert is the path to the server certificate used to start the Minio
	// and STS servers.
	testServerCert string
	// testServerKey is the path to the server key used to start the Minio and STS servers.
	testServerKey string
	// ctx is the common context used in tests.
	ctx context.Context
)

var (
	bucketName = "test-bucket-minio" + uuid.New().String()
	prefix     = ""
	secret     = corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "minio-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"accesskey": []byte(testMinioRootUser),
			"secretkey": []byte(testMinioRootPassword),
		},
		Type: "Opaque",
	}
	emptySecret = corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "minio-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{},
		Type: "Opaque",
	}
	bucket = sourcev1.Bucket{
		ObjectMeta: v1.ObjectMeta{
			Name:      "minio-test-bucket",
			Namespace: "default",
		},
		Spec: sourcev1.BucketSpec{
			BucketName: bucketName,
			Provider:   "generic",
			SecretRef: &meta.LocalObjectReference{
				Name: secret.Name,
			},
		},
	}
	bucketAwsProvider = sourcev1.Bucket{
		ObjectMeta: v1.ObjectMeta{
			Name:      "minio-test-bucket",
			Namespace: "default",
		},
		Spec: sourcev1.BucketSpec{
			BucketName: bucketName,
			Provider:   "aws",
		},
	}
)

func TestMain(m *testing.M) {
	// Initialize common test context
	ctx = context.Background()

	// Uses a sensible default on Windows (TCP/HTTP) and Linux/MacOS (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("could not connect to docker: %s", err)
	}

	// Load a private key and certificate from a self-signed CA for the Minio server and
	// a client TLS configuration to connect to the Minio server.
	testServerCert, testServerKey, testTLSConfig, err = loadServerCertAndClientTLSConfig()
	if err != nil {
		log.Fatalf("could not load server cert and client TLS config: %s", err)
	}

	// Pull the image, create a container based on it, and run it
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "minio/minio",
		Tag:        testMinioVersion,
		ExposedPorts: []string{
			"9000/tcp",
			"9001/tcp",
		},
		Env: []string{
			"MINIO_ROOT_USER=" + testMinioRootUser,
			"MINIO_ROOT_PASSWORD=" + testMinioRootPassword,
		},
		Cmd: []string{"server", "/data", "--console-address", ":9001"},
		Mounts: []string{
			fmt.Sprintf("%s:/root/.minio/certs/public.crt", testServerCert),
			fmt.Sprintf("%s:/root/.minio/certs/private.key", testServerKey),
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
	})
	if err != nil {
		log.Fatalf("could not start resource: %s", err)
	}

	purgeResource := func() {
		if err := pool.Purge(resource); err != nil {
			log.Printf("could not purge resource: %s", err)
		}
	}

	// Set the address of the Minio server used for testing.
	testMinioAddress = fmt.Sprintf("127.0.0.1:%v", resource.GetPort("9000/tcp"))

	// Construct a Minio client using the address of the Minio server.
	testMinioClient, err = NewClient(ctx, bucketStub(bucket, testMinioAddress),
		WithSecret(secret.DeepCopy()),
		WithTLSConfig(testTLSConfig))
	if err != nil {
		log.Fatalf("cannot create Minio client: %s", err)
	}

	// Wait until Minio is ready to serve requests...
	if err := pool.Retry(func() error {
		hCancel, err := testMinioClient.HealthCheck(1 * time.Second)
		if err != nil {
			log.Fatalf("cannot start Minio health check: %s", err)
		}
		defer hCancel()

		if !testMinioClient.IsOnline() {
			return fmt.Errorf("client is offline: Minio is not ready")
		}
		return nil
	}); err != nil {
		purgeResource()
		log.Fatalf("could not connect to docker: %s", err)
	}

	createBucket(ctx)
	addObjectToBucket(ctx)
	run := m.Run()
	removeObjectFromBucket(ctx)
	deleteBucket(ctx)
	purgeResource()
	os.Exit(run)
}

func TestNewClient(t *testing.T) {
	minioClient, err := NewClient(ctx, bucketStub(bucket, testMinioAddress),
		WithSecret(secret.DeepCopy()),
		WithTLSConfig(testTLSConfig))
	g := NewWithT(t)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(minioClient).NotTo(BeNil())
}

func TestNewClientEmptySecret(t *testing.T) {
	minioClient, err := NewClient(ctx, bucketStub(bucket, testMinioAddress),
		WithSecret(emptySecret.DeepCopy()),
		WithTLSConfig(testTLSConfig))
	g := NewWithT(t)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(minioClient).NotTo(BeNil())
}

func TestNewClientAWSProvider(t *testing.T) {
	t.Run("with secret", func(t *testing.T) {
		validSecret := corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name:      "valid-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"accesskey": []byte(testMinioRootUser),
				"secretkey": []byte(testMinioRootPassword),
			},
			Type: "Opaque",
		}

		bucket := bucketStub(bucketAwsProvider, testMinioAddress)
		minioClient, err := NewClient(ctx, bucket, WithSecret(&validSecret))
		g := NewWithT(t)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(minioClient).NotTo(BeNil())
	})

	t.Run("without secret", func(t *testing.T) {
		bucket := bucketStub(bucketAwsProvider, testMinioAddress)
		minioClient, err := NewClient(ctx, bucket)
		g := NewWithT(t)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("AWS authentication failed"))
		g.Expect(minioClient).To(BeNil())
	})
}

func TestBucketExists(t *testing.T) {
	exists, err := testMinioClient.BucketExists(ctx, bucketName)
	g := NewWithT(t)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(exists).To(BeTrue())
}

func TestBucketNotExists(t *testing.T) {
	exists, err := testMinioClient.BucketExists(ctx, "notexistsbucket")
	g := NewWithT(t)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(exists).To(BeFalse())
}

func TestFGetObject(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, sourceignore.IgnoreFile)
	_, err := testMinioClient.FGetObject(ctx, bucketName, objectName, path)
	g := NewWithT(t)
	g.Expect(err).NotTo(HaveOccurred())
}

func TestNewClientAndFGetObjectWithSTSEndpoint(t *testing.T) {
	var credsRetrieved bool

	// start a mock LDAP STS server
	ldapSTSListener, ldapSTSAddr, _ := testlistener.New(t)
	ldapSTSEndpoint := fmt.Sprintf("https://%s", ldapSTSAddr)
	ldapSTSHandler := http.NewServeMux()
	var ldapUsername, ldapPassword string
	ldapSTSHandler.HandleFunc("POST /",
		func(w http.ResponseWriter, r *http.Request) {
			g := NewWithT(t)
			err := r.ParseForm()
			g.Expect(err).NotTo(HaveOccurred())
			username := r.Form.Get("LDAPUsername")
			password := r.Form.Get("LDAPPassword")
			g.Expect(username).To(Equal(ldapUsername))
			g.Expect(password).To(Equal(ldapPassword))
			var result credentials.LDAPIdentityResult
			result.Credentials.AccessKey = testMinioRootUser
			result.Credentials.SecretKey = testMinioRootPassword
			err = xml.NewEncoder(w).Encode(credentials.AssumeRoleWithLDAPResponse{Result: result})
			g.Expect(err).NotTo(HaveOccurred())
			credsRetrieved = true
		})
	ldapSTSServer := &http.Server{
		Addr:    ldapSTSAddr,
		Handler: ldapSTSHandler,
	}
	go ldapSTSServer.ServeTLS(ldapSTSListener, testServerCert, testServerKey)
	defer ldapSTSServer.Shutdown(ctx)

	// start proxy
	proxyAddr, proxyPort := testproxy.New(t)

	tests := []struct {
		name         string
		provider     string
		stsSpec      *sourcev1.BucketSTSSpec
		opts         []Option
		ldapUsername string
		ldapPassword string
		err          string
	}{
		{
			name:     "with correct ldap endpoint",
			provider: "generic",
			stsSpec: &sourcev1.BucketSTSSpec{
				Provider: "ldap",
				Endpoint: ldapSTSEndpoint,
			},
			opts: []Option{WithSTSTLSConfig(testTLSConfig)},
		},
		{
			name:     "with incorrect ldap endpoint",
			provider: "generic",
			stsSpec: &sourcev1.BucketSTSSpec{
				Provider: "ldap",
				Endpoint: fmt.Sprintf("http://localhost:%d", 1),
			},
			err: "connection refused",
		},
		{
			name:     "with correct ldap endpoint and secret",
			provider: "generic",
			stsSpec: &sourcev1.BucketSTSSpec{
				Provider: "ldap",
				Endpoint: ldapSTSEndpoint,
			},
			opts: []Option{
				WithSTSTLSConfig(testTLSConfig),
				WithSTSSecret(&corev1.Secret{
					Data: map[string][]byte{
						"username": []byte("user"),
						"password": []byte("password"),
					},
				}),
			},
			ldapUsername: "user",
			ldapPassword: "password",
		},
		{
			name:     "with correct ldap endpoint and proxy",
			provider: "generic",
			stsSpec: &sourcev1.BucketSTSSpec{
				Provider: "ldap",
				Endpoint: ldapSTSEndpoint,
			},
			opts: []Option{
				WithProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
				WithSTSTLSConfig(testTLSConfig),
			},
		},
		{
			name:     "with correct ldap endpoint and incorrect proxy",
			provider: "generic",
			stsSpec: &sourcev1.BucketSTSSpec{
				Provider: "ldap",
				Endpoint: ldapSTSEndpoint,
			},
			opts: []Option{
				WithProxyURL(&url.URL{Scheme: "http", Host: fmt.Sprintf("localhost:%d", proxyPort+1)}),
			},
			err: "connection refused",
		},
		{
			name:     "with correct ldap endpoint and without client tls config",
			provider: "generic",
			stsSpec: &sourcev1.BucketSTSSpec{
				Provider: "ldap",
				Endpoint: ldapSTSEndpoint,
			},
			err: "tls: failed to verify certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credsRetrieved = false
			ldapUsername = tt.ldapUsername
			ldapPassword = tt.ldapPassword

			bucket := bucketStub(bucket, testMinioAddress)
			bucket.Spec.Provider = tt.provider
			bucket.Spec.STS = tt.stsSpec

			opts := tt.opts
			opts = append(opts, WithTLSConfig(testTLSConfig))

			minioClient, err := NewClient(ctx, bucket, opts...)
			g := NewWithT(t)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(minioClient).NotTo(BeNil())

			path := filepath.Join(t.TempDir(), sourceignore.IgnoreFile)
			_, err = minioClient.FGetObject(ctx, bucketName, objectName, path)
			if tt.err != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.err))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(credsRetrieved).To(BeTrue())
			}
		})
	}
}

func TestNewClientAndFGetObjectWithProxy(t *testing.T) {
	proxyAddr, proxyPort := testproxy.New(t)

	tests := []struct {
		name         string
		proxyURL     *url.URL
		errSubstring string
	}{
		{
			name:     "with correct proxy",
			proxyURL: &url.URL{Scheme: "http", Host: proxyAddr},
		},
		{
			name:         "with incorrect proxy",
			proxyURL:     &url.URL{Scheme: "http", Host: fmt.Sprintf("localhost:%d", proxyPort+1)},
			errSubstring: "connection refused",
		},
	}

	// run test
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			minioClient, err := NewClient(ctx, bucketStub(bucket, testMinioAddress),
				WithSecret(secret.DeepCopy()),
				WithTLSConfig(testTLSConfig),
				WithProxyURL(tt.proxyURL))
			g := NewWithT(t)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(minioClient).NotTo(BeNil())
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, sourceignore.IgnoreFile)
			_, err = minioClient.FGetObject(ctx, bucketName, objectName, path)
			if tt.errSubstring != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.errSubstring))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
			}
		})
	}
}

func TestFGetObjectNotExists(t *testing.T) {
	tempDir := t.TempDir()
	badKey := "invalid.txt"
	path := filepath.Join(tempDir, badKey)
	_, err := testMinioClient.FGetObject(ctx, bucketName, badKey, path)
	g := NewWithT(t)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(Equal("The specified key does not exist."))
	g.Expect(testMinioClient.ObjectIsNotFound(err)).To(BeTrue())
}

func TestVisitObjects(t *testing.T) {
	keys := []string{}
	etags := []string{}
	err := testMinioClient.VisitObjects(context.TODO(), bucketName, prefix, func(key, etag string) error {
		keys = append(keys, key)
		etags = append(etags, etag)
		return nil
	})
	g := NewWithT(t)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(keys).To(Equal([]string{objectName}))
	g.Expect(etags).To(Equal([]string{objectEtag}))
}

func TestVisitObjectsErr(t *testing.T) {
	badBucketName := "bad-bucket"
	err := testMinioClient.VisitObjects(ctx, badBucketName, prefix, func(string, string) error {
		return nil
	})
	g := NewWithT(t)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(Equal(fmt.Sprintf("listing objects from bucket '%s' failed: The specified bucket does not exist", badBucketName)))
}

func TestVisitObjectsCallbackErr(t *testing.T) {
	mockErr := fmt.Errorf("mock")
	err := testMinioClient.VisitObjects(context.TODO(), bucketName, prefix, func(key, etag string) error {
		return mockErr
	})
	g := NewWithT(t)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(Equal(mockErr.Error()))
}

func TestValidateSecret(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		secret *corev1.Secret
		error  bool
	}{
		{
			name:   "valid secret",
			secret: secret.DeepCopy(),
		},
		{
			name:   "nil secret",
			secret: nil,
		},
		{
			name:   "invalid secret",
			secret: emptySecret.DeepCopy(),
			error:  true,
		},
	}
	for _, testCase := range testCases {
		tt := testCase
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := NewWithT(t)
			err := ValidateSecret(tt.secret)
			if tt.error {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(Equal(fmt.Sprintf("invalid '%v' secret data: required fields 'accesskey' and 'secretkey'", tt.secret.Name)))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
			}
		})
	}
}

func TestValidateSTSProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		bucketProvider string
		stsProvider    string
		withSecret     bool
		withCertSecret bool
		err            string
	}{
		{
			name:           "aws",
			bucketProvider: "aws",
			stsProvider:    "aws",
		},
		{
			name:           "aws does not require a secret",
			bucketProvider: "aws",
			stsProvider:    "aws",
			withSecret:     true,
			err:            "spec.sts.secretRef is not required for the 'aws' STS provider",
		},
		{
			name:           "aws does not require a cert secret",
			bucketProvider: "aws",
			stsProvider:    "aws",
			withCertSecret: true,
			err:            "spec.sts.certSecretRef is not required for the 'aws' STS provider",
		},
		{
			name:           "ldap",
			bucketProvider: "generic",
			stsProvider:    "ldap",
		},
		{
			name:           "ldap may use a secret",
			bucketProvider: "generic",
			stsProvider:    "ldap",
			withSecret:     true,
		},
		{
			name:           "ldap may use a cert secret",
			bucketProvider: "generic",
			stsProvider:    "ldap",
			withCertSecret: true,
		},
		{
			name:           "ldap sts provider unsupported for aws bucket provider",
			bucketProvider: "aws",
			stsProvider:    "ldap",
			err:            "STS provider 'ldap' is not supported for 'aws' bucket provider",
		},
		{
			name:           "aws sts provider unsupported for generic bucket provider",
			bucketProvider: "generic",
			stsProvider:    "aws",
			err:            "STS provider 'aws' is not supported for 'generic' bucket provider",
		},
		{
			name:           "unsupported bucket provider",
			bucketProvider: "gcp",
			stsProvider:    "ldap",
			err:            "STS configuration is not supported for 'gcp' bucket provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sts := &sourcev1.BucketSTSSpec{
				Provider: tt.stsProvider,
			}
			if tt.withSecret {
				sts.SecretRef = &meta.LocalObjectReference{}
			}
			if tt.withCertSecret {
				sts.CertSecretRef = &meta.LocalObjectReference{}
			}
			g := NewWithT(t)
			err := ValidateSTSProvider(tt.bucketProvider, sts)
			if tt.err != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(Equal(tt.err))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
			}
		})
	}
}

func TestValidateSTSSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider string
		secret   *corev1.Secret
		err      string
	}{
		{
			name:     "ldap provider does not require a secret",
			provider: "ldap",
		},
		{
			name:     "valid ldap secret",
			provider: "ldap",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
				},
			},
		},
		{
			name:     "empty ldap secret",
			provider: "ldap",
			secret:   &corev1.Secret{ObjectMeta: v1.ObjectMeta{Name: "ldap-secret"}},
			err:      "invalid 'ldap-secret' secret data for 'ldap' STS provider: required fields username, password",
		},
		{
			name:     "ldap secret missing password",
			provider: "ldap",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"username": []byte("user"),
				},
			},
			err: "invalid '' secret data for 'ldap' STS provider: required fields username, password",
		},
		{
			name:     "ldap secret missing username",
			provider: "ldap",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"password": []byte("pass"),
				},
			},
			err: "invalid '' secret data for 'ldap' STS provider: required fields username, password",
		},
		{
			name:     "ldap secret with empty username",
			provider: "ldap",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"username": []byte(""),
					"password": []byte("pass"),
				},
			},
			err: "invalid '' secret data for 'ldap' STS provider: required fields username, password",
		},
		{
			name:     "ldap secret with empty password",
			provider: "ldap",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte(""),
				},
			},
			err: "invalid '' secret data for 'ldap' STS provider: required fields username, password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := NewWithT(t)
			err := ValidateSTSSecret(tt.provider, tt.secret)
			if tt.err != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(Equal(tt.err))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
			}
		})
	}
}

func bucketStub(bucket sourcev1.Bucket, endpoint string) *sourcev1.Bucket {
	b := bucket.DeepCopy()
	b.Spec.Endpoint = endpoint
	b.Spec.Insecure = false
	return b
}

func createBucket(ctx context.Context) {
	if err := testMinioClient.Client.MakeBucket(ctx, bucketName, miniov7.MakeBucketOptions{}); err != nil {
		exists, errBucketExists := testMinioClient.BucketExists(ctx, bucketName)
		if errBucketExists == nil && exists {
			deleteBucket(ctx)
		} else {
			log.Fatalf("could not create bucket: %s", err)
		}
	}
}

func deleteBucket(ctx context.Context) {
	if err := testMinioClient.Client.RemoveBucket(ctx, bucketName); err != nil {
		log.Println(err)
	}
}

func addObjectToBucket(ctx context.Context) {
	fileReader := strings.NewReader(getObjectFile())
	fileSize := fileReader.Size()
	_, err := testMinioClient.Client.PutObject(ctx, bucketName, objectName, fileReader, fileSize, miniov7.PutObjectOptions{
		ContentType: "text/x-yaml",
	})
	if err != nil {
		log.Println(err)
	}
}

func removeObjectFromBucket(ctx context.Context) {
	if err := testMinioClient.Client.RemoveObject(ctx, bucketName, objectName, miniov7.RemoveObjectOptions{
		GovernanceBypass: true,
	}); err != nil {
		log.Println(err)
	}
}

func getObjectFile() string {
	return `
	apiVersion: source.werf.io/v1
	kind: Bucket
	metadata:
	  name: podinfo
	  namespace: default
	spec:
	  interval: 5m
	  provider: aws
	  bucketName: podinfo
	  endpoint: s3.amazonaws.com
	  region: us-east-1
	  timeout: 30s
	`
}

func loadServerCertAndClientTLSConfig() (serverCert string, serverKey string, clientConf *tls.Config, err error) {
	const certsDir = "../../controller/testdata/certs"
	clientConf = &tls.Config{}

	serverCert, err = filepath.Abs(filepath.Join(certsDir, "server.pem"))
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to get server cert path: %w", err)
	}
	serverKey, err = filepath.Abs(filepath.Join(certsDir, "server-key.pem"))
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to get server key path: %w", err)
	}

	b, err := os.ReadFile(filepath.Join(certsDir, "ca.pem"))
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to load CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(b) {
		return "", "", nil, errors.New("failed to append CA to pool")
	}
	clientConf.RootCAs = caPool

	clientCert := filepath.Join(certsDir, "client.pem")
	clientKey := filepath.Join(certsDir, "client-key.pem")
	client, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to load client cert and key: %w", err)
	}
	clientConf.Certificates = []tls.Certificate{client}

	return
}
