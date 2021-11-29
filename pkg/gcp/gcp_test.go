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

package gcp_test

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
	"os"
	"path/filepath"
	"testing"
	"time"

	gcpstorage "cloud.google.com/go/storage"
	"github.com/fluxcd/source-controller/pkg/gcp"
	"google.golang.org/api/googleapi"
	raw "google.golang.org/api/storage/v1"
	"gotest.tools/assert"

	"google.golang.org/api/option"
)

const (
	bucketName string = "test-bucket"
	objectName string = "test.yaml"
)

var (
	hc     *http.Client
	client *gcpstorage.Client
	close  func()
	err    error
)

func TestMain(m *testing.M) {
	hc, close = newTestServer(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.RequestURI == fmt.Sprintf("/storage/v1/b/%s?alt=json&prettyPrint=false&projection=full", bucketName) {
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
		} else if r.RequestURI == fmt.Sprintf("/storage/v1/b/%s/o/%s?alt=json&prettyPrint=false&projection=full", bucketName, objectName) {
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
		} else if r.RequestURI == fmt.Sprintf("/storage/v1/b/%s/o?alt=json&delimiter=&endOffset=&pageToken=&prefix=&prettyPrint=false&projection=full&startOffset=&versions=false", bucketName) {
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
		} else if r.RequestURI == fmt.Sprintf("/%s/test.yaml", bucketName) || r.RequestURI == fmt.Sprintf("/storage/v1/b/%s/o/%s?alt=json&prettyPrint=false&projection=full", bucketName, objectName) {
			w.WriteHeader(200)
			response := getObjectFile()
			_, err = w.Write([]byte(response))
			if err != nil {
				log.Fatalf("error writing response %v\n", err)
			}
		} else {
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

func TestNewClient(t *testing.T) {
	gcpClient, err := gcp.NewClient(context.Background(), option.WithHTTPClient(hc))
	assert.NilError(t, err)
	assert.Assert(t, gcpClient != nil)
}

func TestBucketExists(t *testing.T) {
	gcpClient := &gcp.GCPClient{
		Client: client,
	}
	exists, err := gcpClient.BucketExists(context.Background(), bucketName)
	assert.NilError(t, err)
	assert.Assert(t, exists)
}

func TestBucketNotExists(t *testing.T) {
	bucket := "notexistsbucket"
	gcpClient := &gcp.GCPClient{
		Client: client,
	}
	exists, err := gcpClient.BucketExists(context.Background(), bucket)
	assert.NilError(t, err)
	assert.Assert(t, !exists)
}

func TestObjectExists(t *testing.T) {
	gcpClient := &gcp.GCPClient{
		Client: client,
	}
	exists, err := gcpClient.ObjectExists(context.Background(), bucketName, objectName)
	if err == gcpstorage.ErrObjectNotExist {
		assert.NilError(t, err)
	}
	assert.NilError(t, err)
	assert.Assert(t, exists)
}

func TestObjectNotExists(t *testing.T) {
	object := "doesnotexists.yaml"
	gcpClient := &gcp.GCPClient{
		Client: client,
	}
	exists, err := gcpClient.ObjectExists(context.Background(), bucketName, object)
	assert.Error(t, err, gcpstorage.ErrObjectNotExist.Error())
	assert.Assert(t, !exists)
}

func TestListObjects(t *testing.T) {
	gcpClient := &gcp.GCPClient{
		Client: client,
	}
	objectIterator := gcpClient.ListObjects(context.Background(), bucketName, nil)
	for {
		_, err := objectIterator.Next()
		if err == gcp.IteratorDone {
			break
		}
		assert.NilError(t, err)
	}
	assert.Assert(t, objectIterator != nil)
}

func TestFGetObject(t *testing.T) {
	tempDir, err := os.MkdirTemp("", bucketName)
	assert.NilError(t, err)
	defer os.RemoveAll(tempDir)
	gcpClient := &gcp.GCPClient{
		Client: client,
	}
	localPath := filepath.Join(tempDir, objectName)
	err = gcpClient.FGetObject(context.Background(), bucketName, objectName, localPath)
	if err != io.EOF {
		assert.NilError(t, err)
	}
}

func TestFGetObjectNotExists(t *testing.T) {
	object := "notexists.txt"
	tempDir, err := os.MkdirTemp("", bucketName)
	assert.NilError(t, err)
	defer os.RemoveAll(tempDir)
	gcpClient := &gcp.GCPClient{
		Client: client,
	}
	localPath := filepath.Join(tempDir, object)
	err = gcpClient.FGetObject(context.Background(), bucketName, object, localPath)
	if err != io.EOF {
		assert.Error(t, err, "storage: object doesn't exist")
	}
}

func TestFGetObjectDirectoryIsFileName(t *testing.T) {
	tempDir, err := os.MkdirTemp("", bucketName)
	defer os.RemoveAll(tempDir)
	assert.NilError(t, err)
	gcpClient := &gcp.GCPClient{
		Client: client,
	}
	err = gcpClient.FGetObject(context.Background(), bucketName, objectName, tempDir)
	if err != io.EOF {
		assert.Error(t, err, "filename is a directory")
	}
}

func TestValidateSecret(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		title  string
		secret map[string][]byte
		name   string
		error  bool
	}{
		{
			"Test Case 1",
			map[string][]byte{
				"serviceaccount": []byte("serviceaccount"),
			},
			"Service Account",
			false,
		},
		{
			"Test Case 2",
			map[string][]byte{
				"data": []byte("data"),
			},
			"Service Account",
			true,
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.title, func(t *testing.T) {
			t.Parallel()
			err := gcp.ValidateSecret(testCase.secret, testCase.name)
			if testCase.error {
				assert.Error(t, err, fmt.Sprintf("invalid '%v' secret data: required fields 'serviceaccount'", testCase.name))
			} else {
				assert.NilError(t, err)
			}
		})
	}
}

func newTestServer(handler func(w http.ResponseWriter, r *http.Request)) (*http.Client, func()) {
	ts := httptest.NewTLSServer(http.HandlerFunc(handler))
	tlsConf := &tls.Config{InsecureSkipVerify: true}
	tr := &http.Transport{
		TLSClientConfig: tlsConf,
		DialTLS: func(netw, addr string) (net.Conn, error) {
			return tls.Dial("tcp", ts.Listener.Addr().String(), tlsConf)
		},
	}
	return &http.Client{Transport: tr}, func() {
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
		Md5Hash:                 "bFbHCDvedeecefdgmfmhfuRxBdcedGe96S82XJOAXxjJpk=",
	}
}

func getBucket() *raw.Bucket {
	labels := map[string]string{"a": "b"}
	matchClasses := []string{"STANDARD"}
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
					Age:                 10,
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
