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

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	testproxy "github.com/fluxcd/source-controller/tests/proxy"
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
			"serviceaccount": []byte(serviceAccountJSON),
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
	malformedSecret = corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "gcp-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"serviceaccount": []byte("not-json"),
		},
		Type: "Opaque",
	}
	externalAccountSecret = corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "gcp-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"serviceaccount": []byte(externalAccountJSON),
		},
		Type: "Opaque",
	}
)

// serviceAccountJSON is a dummy GCP service account key. The private key is a
// throwaway RSA key generated for this test only; it does not belong to any
// real service account and cannot be used to retrieve tokens, only to
// exercise credential construction.
const serviceAccountJSON = `{
    "type": "service_account",
    "project_id": "podinfo",
    "private_key_id": "28qwgh3gdf5hj3gb5fj3gsu5yfgh34f45324568hy2",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC02OoAWFKPVfE2\nTVYmdQKb8WRZo8ciQomAYb7WluGqa6avPu/9z7+q4K7hZtN/9Q2t0EvvBuKXTL8+\nV+AUV2N+oi4nY7T2yq3Ebc66R/c21o9sNvYJog6S8HWtOOd0tvotrvrjFQnfcCX5\nzC48HC9PgUjHAeR8kacYlpKbaEobRI1i9AfN5deuS5tsI0Di8Ag6lGf7G+0gHUpM\nLmUttJCleOltOl1Xwb57/zZCgGwB5VdkaBtkq6KW0xxwhOqF1RiFuGOUf+vRNjfj\nLPx58XSTL0TNtYa3M8koBLMaVznY5du6Pqpq1VBSUo3Yw0Z8DwxErZBICkvwbEsQ\njmQNpK+5AgMBAAECgf8l/OqQ5/yi3z3fI9LU55jrHBzx0QiJycnYWq/ocG+dIyYz\ngz6MsiowwSf7CpgJNaojhX2hCz4A474uxyBRJYotlfB1lbXA1KvSEL7Vom64T8zd\njmEtGApRRosLHmKAKDw+tfxwqhqvNLLFcuTDYg6nqyCYE22x1pnWMGR1AJMqGgFr\nSjfTl2wtSQzT705Cd3oNoItqPdYh4Ky6dxImfiHcj237mFXWy9e5x6l0N7ShJzqS\nH3t8s5wnxjt9jAK7NBqCFSxvYyKSO7MTLBlOLUdM8KuzjsYgKw0e2j+D4LhXKc/N\n1nXY2hUgq4NAOnYoK4HUAkOcN34wLjxTvp6wlwECgYEA7pkh0/QPrGVZ9bjAExq6\nCY9Z+gejUDOHWl4aWQeZA36g3FvlPgHTFTB7hMbmABbVEjCbLrnSFe9aMQsYm0O2\n/4MAUAqXX9bV134YK3kbtYH2qXX/60oGjACcbx0CIzOAO8prF7h0MKol065POaK8\nLGupztnn1fP/cH3GXF/cVLkCgYEAwgmD874uAYrXGPZ25PjH+J+L2IGj7WIa173O\ni+WJe/5Lp/A/fp9zr/ln5x2t5Pg7btysayGz1e8TGfrEBJ8ADzIm9z9ale9XHRz5\nVIBqO+bh3PW+iBs2ocZkfMtXigDCkIBP/lutvzvcFN/fsvGw1DF8PCmN6no6/gC5\nwzNjswECgYEAmbzp4xx7jOWxVXc5rBWokchgfY62WFMbf8rqxzryCSJqnBJKX+3l\nCN44eJGAWcZcfF/9Xdo12BRl1PwFWuYC4BiU9v4cE5DmMPf6suhSRl37ha2WvRDx\nrvwl0CKs4empUt1Wq+4aT9ESlpbWTZjiDu1AeRxHGcEicmVYjuTln2ECgYEAkciC\naiQN/ryoxSmPxJKh88szT7R/TD/0OPlzcKpBdHZns0KPAfyc967kAMHMwAY86RtF\nM6x7qBVafZ9pnKs1aTVeD097KMFM6yO0tGdS6bSbJ98+ipYfosYjA5vnJllR1S2C\nbHHHBbHctZZKRPDP0W1okO8LoAq7vdEfwGgg1QECgYBBuHECqDcz+buKSZRAQqRm\ngqt4hdcu+qRMqleZY4WPNHAZoPna9hU+7EFM+D1qsB6iZxzsUXzKF9gmJfB+Zvcn\nmLQq0YXDeXBt2KWeQSyQLM2bBW0J3aFIpilaP3VRcXUPEF7FstT0DC+SkydbANIf\n5IiZW7E1qU/WBIWMkD4WuA==\n-----END PRIVATE KEY-----\n",
    "client_email": "test@podinfo.iam.gserviceaccount.com",
    "client_id": "32657634678762536746",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%40podinfo.iam.gserviceaccount.com"
}`

// externalAccountJSON is a workload identity federation configuration, which
// is not a supported credential type for the 'serviceaccount' secret field.
const externalAccountJSON = `{
    "type": "external_account",
    "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/v",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "token_url": "https://sts.googleapis.com/v1/token",
    "credential_source": {
        "file": "/var/run/service-account/token"
    }
}`

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

func TestNewClientWithSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  *corev1.Secret
		wantErr string
	}{
		{
			name:   "service account key",
			secret: secret.DeepCopy(),
		},
		{
			name:    "missing serviceaccount field",
			secret:  badSecret.DeepCopy(),
			wantErr: "invalid 'gcp-secret' secret data: required fields 'serviceaccount'",
		},
		{
			name:    "serviceaccount is not JSON",
			secret:  malformedSecret.DeepCopy(),
			wantErr: "invalid 'gcp-secret' secret data: failed to parse 'serviceaccount' as JSON",
		},
		{
			name:    "unsupported credential type",
			secret:  externalAccountSecret.DeepCopy(),
			wantErr: "invalid 'gcp-secret' secret data: 'serviceaccount' must contain a service account key with 'type' set to 'service_account'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			gcpClient, err := NewClient(context.Background(), createTestBucket(), WithSecret(tt.secret))
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(Equal(tt.wantErr))
				g.Expect(gcpClient).To(BeNil())
				return
			}
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(gcpClient).NotTo(BeNil())
			gcpClient.Close(context.Background())
		})
	}
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
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(gcpClient).NotTo(BeNil())
		gcpClient.Close(context.Background())
	})

	t.Run("with unsupported credential type", func(t *testing.T) {
		g := NewWithT(t)
		bucket := createTestBucket()
		gcpClient, err := NewClient(context.Background(), bucket,
			WithProxyURL(&url.URL{}),
			WithSecret(externalAccountSecret.DeepCopy()))
		g.Expect(err).To(HaveOccurred())
		g.Expect(gcpClient).To(BeNil())
		g.Expect(err.Error()).To(Equal("invalid 'gcp-secret' secret data: 'serviceaccount' must contain a service account key with 'type' set to 'service_account'"))
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
		name    string
		secret  *corev1.Secret
		wantErr string
	}{
		{
			name:   "nil secret",
			secret: nil,
		},
		{
			name:   "service account key",
			secret: secret.DeepCopy(),
		},
		{
			name:    "missing serviceaccount field",
			secret:  badSecret.DeepCopy(),
			wantErr: "invalid 'gcp-secret' secret data: required fields 'serviceaccount'",
		},
		{
			name:    "serviceaccount is not JSON",
			secret:  malformedSecret.DeepCopy(),
			wantErr: "invalid 'gcp-secret' secret data: failed to parse 'serviceaccount' as JSON",
		},
		{
			name:    "unsupported credential type",
			secret:  externalAccountSecret.DeepCopy(),
			wantErr: "invalid 'gcp-secret' secret data: 'serviceaccount' must contain a service account key with 'type' set to 'service_account'",
		},
	}
	for _, testCase := range testCases {
		tt := testCase
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateSecret(tt.secret)
			g := NewWithT(t)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(Equal(tt.wantErr))
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
	apiVersion: source.toolkit.fluxcd.io/v1beta1
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
