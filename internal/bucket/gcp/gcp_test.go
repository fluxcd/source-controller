/*
Copyright 2021 The Flux authors

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

package gcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloud.google.com/go/compute/metadata"
	gcpstorage "cloud.google.com/go/storage"
	. "github.com/onsi/gomega"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	raw "google.golang.org/api/storage/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
	testproxy "github.com/werf/nelm-source-controller/tests/proxy"
)

const (
	bucketName       string = "test-bucket"
	objectName       string = "test.yaml"
	objectGeneration int64  = 3
	objectEtag       string = "bFbHCDvedeecefdgmfmhfuRxBdcedGe96S82XJOAXxjJpk="
	envGCSHost       string = "STORAGE_EMULATOR_HOST"
	envADC           string = "GOOGLE_APPLICATION_CREDENTIALS"
)

var (
	hc     *http.Client
	host   string
	client *gcpstorage.Client
	close  func()
	err    error
	secret = corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "gcp-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"serviceaccount": []byte("ewogICAgInR5cGUiOiAic2VydmljZV9hY2NvdW50IiwKICAgICJwcm9qZWN0X2lkIjogInBvZGluZm8iLAogICAgInByaXZhdGVfa2V5X2lkIjogIjI4cXdnaDNnZGY1aGozZ2I1ZmozZ3N1NXlmZ2gzNGY0NTMyNDU2OGh5MiIsCiAgICAicHJpdmF0ZV9rZXkiOiAiLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG5Id2V0aGd5MTIzaHVnZ2hoaGJkY3U2MzU2ZGd5amhzdmd2R0ZESFlnY2RqYnZjZGhic3g2M2Ncbjc2dGd5Y2ZlaHVoVkdURllmdzZ0N3lkZ3lWZ3lkaGV5aHVnZ3ljdWhland5NnQzNWZ0aHl1aGVndmNldGZcblRGVUhHVHlnZ2h1Ymh4ZTY1eWd0NnRneWVkZ3kzMjZodWN5dnN1aGJoY3Zjc2poY3NqaGNzdmdkdEhGQ0dpXG5IY3llNnR5eWczZ2Z5dWhjaGNzYmh5Z2NpamRiaHl5VEY2NnR1aGNldnVoZGNiaHVoaHZmdGN1aGJoM3VoN3Q2eVxuZ2d2ZnRVSGJoNnQ1cmZ0aGh1R1ZSdGZqaGJmY3JkNXI2N3l1aHV2Z0ZUWWpndnRmeWdoYmZjZHJoeWpoYmZjdGZkZnlodmZnXG50Z3ZnZ3RmeWdodmZ0NnR1Z3ZURjVyNjZ0dWpoZ3ZmcnR5aGhnZmN0Nnk3eXRmcjVjdHZnaGJoaHZ0Z2hoanZjdHRmeWNmXG5mZnhmZ2hqYnZnY2d5dDY3dWpiZ3ZjdGZ5aFZDN3VodmdjeWp2aGhqdnl1amNcbmNnZ2hndmdjZmhnZzc2NTQ1NHRjZnRoaGdmdHloaHZ2eXZ2ZmZnZnJ5eXU3N3JlcmVkc3dmdGhoZ2ZjZnR5Y2ZkcnR0ZmhmL1xuLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLVxuIiwKICAgICJjbGllbnRfZW1haWwiOiAidGVzdEBwb2RpbmZvLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAgICJjbGllbnRfaWQiOiAiMzI2NTc2MzQ2Nzg3NjI1MzY3NDYiLAogICAgImF1dGhfdXJpIjogImh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi9hdXRoIiwKICAgICJ0b2tlbl91cmkiOiAiaHR0cHM6Ly9vYXV0aDIuZ29vZ2xlYXBpcy5jb20vdG9rZW4iLAogICAgImF1dGhfcHJvdmlkZXJfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9vYXV0aDIvdjEvY2VydHMiLAogICAgImNsaWVudF94NTA5X2NlcnRfdXJsIjogImh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL3JvYm90L3YxL21ldGFkYXRhL3g1MDkvdGVzdCU0MHBvZGluZm8uaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iCn0="),
		},
		Type: "Opaque",
	}
	badSecret = corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "gcp-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte("test-user"),
		},
		Type: "Opaque",
	}
)

// createTestBucket creates a test bucket for testing purposes
func createTestBucket() *sourcev1.Bucket {
	return &sourcev1.Bucket{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-bucket",
			Namespace: "default",
		},
		Spec: sourcev1.BucketSpec{
			BucketName: bucketName,
			Endpoint:   "storage.googleapis.com",
			Provider:   sourcev1.BucketProviderGoogle,
			Interval:   v1.Duration{Duration: time.Minute * 5},
		},
	}
}

func TestMain(m *testing.M) {
	hc, host, close = newTestServer(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		switch r.RequestURI {
		case fmt.Sprintf("/storage/v1/b/%s?alt=json&prettyPrint=false&projection=full", bucketName):
			w.WriteHeader(200)
			response := getBucket()
			jsonResponse, err := json.Marshal(response)
			if err != nil {
				log.Fatalf("error marshalling response %v\n", err)
			}
			_, err = w.Write(jsonResponse)
			if err != nil {
				log.Fatalf("error writing jsonResponse %v\n", err)
			}
		case fmt.Sprintf("/storage/v1/b/%s/o/%s?alt=json&prettyPrint=false&projection=full", bucketName, objectName):
			w.WriteHeader(200)
			response := getObject()
			jsonResponse, err := json.Marshal(response)
			if err != nil {
				log.Fatalf("error marshalling response %v\n", err)
			}
			_, err = w.Write(jsonResponse)
			if err != nil {
				log.Fatalf("error writing jsonResponse %v\n", err)
			}
		case fmt.Sprintf("/storage/v1/b/%s/o?alt=json&delimiter=&endOffset=&pageToken=&prefix=&prettyPrint=false&projection=full&startOffset=&versions=false", bucketName):
		case fmt.Sprintf("/storage/v1/b/%s/o?alt=json&delimiter=&endOffset=&includeTrailingDelimiter=false&pageToken=&prefix=&prettyPrint=false&projection=full&startOffset=&versions=false", bucketName):
		case fmt.Sprintf("/storage/v1/b/%s/o?alt=json&delimiter=&endOffset=&includeTrailingDelimiter=false&matchGlob=&pageToken=&prefix=&prettyPrint=false&projection=full&startOffset=&versions=false", bucketName):
		case fmt.Sprintf("/storage/v1/b/%s/o?alt=json&delimiter=&endOffset=&includeFoldersAsPrefixes=false&includeTrailingDelimiter=false&matchGlob=&pageToken=&prefix=&prettyPrint=false&projection=full&startOffset=&versions=false", bucketName):
			w.WriteHeader(200)
			response := &raw.Objects{}
			response.Items = append(response.Items, getObject())
			jsonResponse, err := json.Marshal(response)
			if err != nil {
				log.Fatalf("error marshalling response %v\n", err)
			}
			_, err = w.Write(jsonResponse)
			if err != nil {
				log.Fatalf("error writing jsonResponse %v\n", err)
			}
		case fmt.Sprintf("/%s/test.yaml", bucketName),
			fmt.Sprintf("/%s/test.yaml?ifGenerationMatch=%d", bucketName, objectGeneration),
			fmt.Sprintf("/storage/v1/b/%s/o/%s?alt=json&prettyPrint=false&projection=full", bucketName, objectName):
			w.WriteHeader(200)
			response := getObjectFile()
			_, err = w.Write([]byte(response))
			if err != nil {
				log.Fatalf("error writing response %v\n", err)
			}
		default:
			w.WriteHeader(404)
		}
	})
	ctx := context.Background()
	client, err = gcpstorage.NewClient(ctx, option.WithHTTPClient(hc))
	if err != nil {
		log.Fatal(err)
	}
	run := m.Run()
	close()
	os.Exit(run)
}

func TestNewClientWithSecretErr(t *testing.T) {
	bucket := createTestBucket()
	gcpClient, err := NewClient(context.Background(), bucket, WithSecret(secret.DeepCopy()))
	t.Log(err)
	g := NewWithT(t)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(Equal("dialing: invalid character 'e' looking for beginning of value"))
	g.Expect(gcpClient).To(BeNil())
}

func TestNewClientWithProxyErr(t *testing.T) {
	_, envADCIsSet := os.LookupEnv(envADC)
	g := NewWithT(t)
	g.Expect(envADCIsSet).To(BeFalse())
	g.Expect(metadata.OnGCE()).To(BeFalse())

	t.Run("with secret", func(t *testing.T) {
		g := NewWithT(t)
		bucket := createTestBucket()
		gcpClient, err := NewClient(context.Background(), bucket,
			WithProxyURL(&url.URL{}),
			WithSecret(secret.DeepCopy()))
		g.Expect(err).To(HaveOccurred())
		g.Expect(gcpClient).To(BeNil())
		g.Expect(err.Error()).To(Equal("failed to create Google credentials from secret: invalid character 'e' looking for beginning of value"))
	})

	t.Run("without secret", func(t *testing.T) {
		g := NewWithT(t)
		bucket := createTestBucket()
		gcpClient, err := NewClient(context.Background(), bucket,
			WithProxyURL(&url.URL{}))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(gcpClient).NotTo(BeNil())
		bucketAttrs, err := gcpClient.Client.Bucket("some-bucket").Attrs(context.Background())
		g.Expect(err).To(HaveOccurred())
		g.Expect(bucketAttrs).To(BeNil())
		g.Expect(err.Error()).To(ContainSubstring("failed to create provider access token"))
	})
}

func TestProxy(t *testing.T) {
	proxyAddr, proxyPort := testproxy.New(t)

	err := os.Setenv(envGCSHost, fmt.Sprintf("https://%s", host))
	g := NewWithT(t)
	g.Expect(err).NotTo(HaveOccurred())
	defer func() {
		err := os.Unsetenv(envGCSHost)
		g.Expect(err).NotTo(HaveOccurred())
	}()

	tests := []struct {
		name     string
		proxyURL *url.URL
		err      string
	}{
		{
			name:     "with correct address",
			proxyURL: &url.URL{Scheme: "http", Host: proxyAddr},
		},
		{
			name:     "with incorrect address",
			proxyURL: &url.URL{Scheme: "http", Host: fmt.Sprintf("localhost:%d", proxyPort+1)},
			err:      "connection refused",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			opts := []Option{WithProxyURL(tt.proxyURL)}
			opts = append(opts, func(o *options) {
				o.newCustomHTTPClient = func(ctx context.Context, o *options) (*http.Client, error) {
					transport := &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
						Proxy:           http.ProxyURL(o.proxyURL),
					}
					return &http.Client{Transport: transport}, nil
				}
			})
			bucket := createTestBucket()
			gcpClient, err := NewClient(context.Background(), bucket, opts...)
			g := NewWithT(t)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(gcpClient).NotTo(BeNil())
			gcpClient.Client.SetRetry(gcpstorage.WithMaxAttempts(1))
			exists, err := gcpClient.BucketExists(context.Background(), bucketName)
			if tt.err != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.err))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(exists).To(BeTrue())
			}
		})
	}
}

func TestBucketExists(t *testing.T) {
	gcpClient := &GCSClient{
		Client: client,
	}
	exists, err := gcpClient.BucketExists(context.Background(), bucketName)
	g := NewWithT(t)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(exists).To(BeTrue())
}

func TestBucketNotExists(t *testing.T) {
	bucket := "notexistsbucket"
	gcpClient := &GCSClient{
		Client: client,
	}
	exists, err := gcpClient.BucketExists(context.Background(), bucket)
	g := NewWithT(t)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(exists).To(BeFalse())
}

func TestVisitObjects(t *testing.T) {
	gcpClient := &GCSClient{
		Client: client,
	}
	keys := []string{}
	etags := []string{}
	err := gcpClient.VisitObjects(context.Background(), bucketName, "", func(key, etag string) error {
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
	g := NewWithT(t)
	gcpClient := &GCSClient{
		Client: client,
	}
	badBucketName := "bad-bucket"
	err := gcpClient.VisitObjects(context.Background(), badBucketName, "", func(key, etag string) error {
		return nil
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring(
		fmt.Sprintf("listing objects from bucket '%s' failed: storage: bucket doesn't exist", badBucketName)))
}

func TestVisitObjectsCallbackErr(t *testing.T) {
	gcpClient := &GCSClient{
		Client: client,
	}
	mockErr := fmt.Errorf("mock")
	err := gcpClient.VisitObjects(context.Background(), bucketName, "", func(key, etag string) error {
		return mockErr
	})
	g := NewWithT(t)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(Equal(mockErr.Error()))
}

func TestFGetObject(t *testing.T) {
	g := NewWithT(t)
	tempDir := t.TempDir()
	gcpClient := &GCSClient{
		Client: client,
	}
	localPath := filepath.Join(tempDir, objectName)
	etag, err := gcpClient.FGetObject(context.Background(), bucketName, objectName, localPath)
	if err != io.EOF {
		g.Expect(err).NotTo(HaveOccurred())
	}
	g.Expect(etag).To(Equal(objectEtag))
}

func TestFGetObjectNotExists(t *testing.T) {
	g := NewWithT(t)
	object := "notexists.txt"
	tempDir := t.TempDir()
	gcsClient := &GCSClient{
		Client: client,
	}
	localPath := filepath.Join(tempDir, object)
	_, err := gcsClient.FGetObject(context.Background(), bucketName, object, localPath)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("storage: object doesn't exist"))
}

func TestFGetObjectDirectoryIsFileName(t *testing.T) {
	g := NewWithT(t)
	tempDir := t.TempDir()
	gcpClient := &GCSClient{
		Client: client,
	}
	_, err = gcpClient.FGetObject(context.Background(), bucketName, objectName, tempDir)
	if err != io.EOF {
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(Equal("filename is a directory"))
	}
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
			name:   "invalid secret",
			secret: badSecret.DeepCopy(),
			error:  true,
		},
	}
	for _, testCase := range testCases {
		tt := testCase
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateSecret(tt.secret)
			g := NewWithT(t)
			if tt.error {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(Equal(fmt.Sprintf("invalid '%v' secret data: required fields 'serviceaccount'", tt.secret.Name)))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
			}
		})
	}
}

func newTestServer(handler func(w http.ResponseWriter, r *http.Request)) (*http.Client, string, func()) {
	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	host := ts.Listener.Addr().String()
	tlsConf := &tls.Config{InsecureSkipVerify: true}
	tr := &http.Transport{
		TLSClientConfig: tlsConf,
		DialTLS: func(netw, addr string) (net.Conn, error) {
			return tls.Dial("tcp", host, tlsConf)
		},
	}
	return &http.Client{Transport: tr}, host, func() {
		tr.CloseIdleConnections()
		ts.Close()
	}
}

func getObject() *raw.Object {
	customTime := time.Now()
	retTime := customTime.Add(3 * time.Hour)
	return &raw.Object{
		Bucket:                  bucketName,
		Name:                    objectName,
		EventBasedHold:          false,
		TemporaryHold:           false,
		RetentionExpirationTime: retTime.Format(time.RFC3339),
		ContentType:             "text/x-yaml",
		ContentLanguage:         "en-us",
		Size:                    1 << 20,
		CustomTime:              customTime.Format(time.RFC3339),
		Generation:              objectGeneration,
		Metageneration:          3,
		Etag:                    objectEtag,
		Md5Hash:                 objectEtag,
	}
}

func getBucket() *raw.Bucket {
	labels := map[string]string{"a": "b"}
	matchClasses := []string{"STANDARD"}
	age := int64(10)
	aTime := time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC)
	rb := &raw.Bucket{
		Name:                  bucketName,
		Location:              "loc",
		DefaultEventBasedHold: true,
		Metageneration:        3,
		StorageClass:          "sc",
		TimeCreated:           "2021-5-23T04:05:06Z",
		Versioning:            &raw.BucketVersioning{Enabled: true},
		Labels:                labels,
		Billing:               &raw.BucketBilling{RequesterPays: true},
		Etag:                  "BNaB2y5Xr3&5MHDca4SoTNL79lyhahr7MV87ubwjgdtg6ghs",
		Lifecycle: &raw.BucketLifecycle{
			Rule: []*raw.BucketLifecycleRule{{
				Action: &raw.BucketLifecycleRuleAction{
					Type:         "SetStorageClass",
					StorageClass: "NEARLINE",
				},
				Condition: &raw.BucketLifecycleRuleCondition{
					Age:                 &age,
					IsLive:              googleapi.Bool(true),
					CreatedBefore:       "2021-01-02",
					MatchesStorageClass: matchClasses,
					NumNewerVersions:    3,
				},
			}},
		},
		RetentionPolicy: &raw.BucketRetentionPolicy{
			RetentionPeriod: 3,
			EffectiveTime:   aTime.Format(time.RFC3339),
		},
		IamConfiguration: &raw.BucketIamConfiguration{
			BucketPolicyOnly: &raw.BucketIamConfigurationBucketPolicyOnly{
				Enabled:    true,
				LockedTime: aTime.Format(time.RFC3339),
			},
			UniformBucketLevelAccess: &raw.BucketIamConfigurationUniformBucketLevelAccess{
				Enabled:    true,
				LockedTime: aTime.Format(time.RFC3339),
			},
		},
		Cors: []*raw.BucketCors{
			{
				MaxAgeSeconds:  3600,
				Method:         []string{"GET", "POST"},
				Origin:         []string{"*"},
				ResponseHeader: []string{"FOO"},
			},
		},
		Acl: []*raw.BucketAccessControl{
			{Bucket: bucketName, Role: "READER", Email: "test@example.com", Entity: "allUsers"},
		},
		LocationType: "dual-region",
		Encryption:   &raw.BucketEncryption{DefaultKmsKeyName: "key"},
		Logging:      &raw.BucketLogging{LogBucket: "lb", LogObjectPrefix: "p"},
		Website:      &raw.BucketWebsite{MainPageSuffix: "mps", NotFoundPage: "404"},
	}
	return rb
}

func getObjectFile() string {
	return `
	apiVersion: source.werf.io/v1beta1
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
