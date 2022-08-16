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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/sourceignore"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"

	"github.com/google/uuid"
	miniov7 "github.com/minio/minio-go/v7"
	"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	objectName string = "test.yaml"
	objectEtag string = "2020beab5f1711919157756379622d1d"
)

var (
	minioClient *MinioClient
	bucketName  = "test-bucket-minio" + uuid.New().String()
	secret      = corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "minio-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"accesskey": []byte("Q3AM3UQ867SPQQA43P2F"),
			"secretkey": []byte("zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG"),
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
			Endpoint:   "play.min.io",
			Provider:   "generic",
			Insecure:   true,
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
			Endpoint:   "play.min.io",
			Provider:   "aws",
			Insecure:   true,
		},
	}
)

func TestMain(m *testing.M) {
	var err error
	ctx := context.Background()
	minioClient, err = NewClient(bucket.DeepCopy(), secret.DeepCopy())
	if err != nil {
		log.Fatal(err)
	}
	createBucket(ctx)
	addObjectToBucket(ctx)
	run := m.Run()
	removeObjectFromBucket(ctx)
	deleteBucket(ctx)
	os.Exit(run)
}

func TestNewClient(t *testing.T) {
	minioClient, err := NewClient(bucket.DeepCopy(), secret.DeepCopy())
	assert.NilError(t, err)
	assert.Assert(t, minioClient != nil)
}

func TestNewClientEmptySecret(t *testing.T) {
	minioClient, err := NewClient(bucket.DeepCopy(), emptySecret.DeepCopy())
	assert.NilError(t, err)
	assert.Assert(t, minioClient != nil)
}

func TestNewClientAwsProvider(t *testing.T) {
	minioClient, err := NewClient(bucketAwsProvider.DeepCopy(), nil)
	assert.NilError(t, err)
	assert.Assert(t, minioClient != nil)
}

func TestBucketExists(t *testing.T) {
	ctx := context.Background()
	exists, err := minioClient.BucketExists(ctx, bucketName)
	assert.NilError(t, err)
	assert.Assert(t, exists)
}

func TestBucketNotExists(t *testing.T) {
	ctx := context.Background()
	exists, err := minioClient.BucketExists(ctx, "notexistsbucket")
	assert.NilError(t, err)
	assert.Assert(t, !exists)
}

func TestFGetObject(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, sourceignore.IgnoreFile)
	_, err := minioClient.FGetObject(ctx, bucketName, objectName, path)
	assert.NilError(t, err)
}

func TestFGetObjectNotExists(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	badKey := "invalid.txt"
	path := filepath.Join(tempDir, badKey)
	_, err := minioClient.FGetObject(ctx, bucketName, badKey, path)
	assert.Error(t, err, "The specified key does not exist.")
	assert.Check(t, minioClient.ObjectIsNotFound(err))
}

func TestVisitObjects(t *testing.T) {
	keys := []string{}
	etags := []string{}
	err := minioClient.VisitObjects(context.TODO(), bucketName, func(key, etag string) error {
		keys = append(keys, key)
		etags = append(etags, etag)
		return nil
	})
	assert.NilError(t, err)
	assert.DeepEqual(t, keys, []string{objectName})
	assert.DeepEqual(t, etags, []string{objectEtag})
}

func TestVisitObjectsErr(t *testing.T) {
	ctx := context.Background()
	badBucketName := "bad-bucket"
	err := minioClient.VisitObjects(ctx, badBucketName, func(string, string) error {
		return nil
	})
	assert.Error(t, err, fmt.Sprintf("listing objects from bucket '%s' failed: The specified bucket does not exist", badBucketName))
}

func TestVisitObjectsCallbackErr(t *testing.T) {
	mockErr := fmt.Errorf("mock")
	err := minioClient.VisitObjects(context.TODO(), bucketName, func(key, etag string) error {
		return mockErr
	})
	assert.Error(t, err, mockErr.Error())
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
			err := ValidateSecret(tt.secret)
			if tt.error {
				assert.Error(t, err, fmt.Sprintf("invalid '%v' secret data: required fields 'accesskey' and 'secretkey'", tt.secret.Name))
			} else {
				assert.NilError(t, err)
			}
		})
	}
}

func createBucket(ctx context.Context) {
	if err := minioClient.Client.MakeBucket(ctx, bucketName, miniov7.MakeBucketOptions{}); err != nil {
		exists, errBucketExists := minioClient.BucketExists(ctx, bucketName)
		if errBucketExists == nil && exists {
			deleteBucket(ctx)
		} else {
			log.Fatalln(err)
		}
	}
}

func deleteBucket(ctx context.Context) {
	if err := minioClient.Client.RemoveBucket(ctx, bucketName); err != nil {
		log.Println(err)
	}
}

func addObjectToBucket(ctx context.Context) {
	fileReader := strings.NewReader(getObjectFile())
	fileSize := fileReader.Size()
	_, err := minioClient.Client.PutObject(ctx, bucketName, objectName, fileReader, fileSize, miniov7.PutObjectOptions{
		ContentType: "text/x-yaml",
	})
	if err != nil {
		log.Println(err)
	}
}

func removeObjectFromBucket(ctx context.Context) {
	if err := minioClient.Client.RemoveObject(ctx, bucketName, objectName, miniov7.RemoveObjectOptions{
		GovernanceBypass: true,
	}); err != nil {
		log.Println(err)
	}
}

func getObjectFile() string {
	return `
	apiVersion: source.toolkit.fluxcd.io/v1beta2
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
