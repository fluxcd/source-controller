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
package minio_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fluxcd/pkg/apis/meta"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/pkg/minio"
	"github.com/fluxcd/source-controller/pkg/sourceignore"

	"github.com/google/uuid"
	miniov7 "github.com/minio/minio-go/v7"
	"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	objectName string = "test.yaml"
	region     string = "us-east-1"
)

var (
	minioclient *minio.MinioClient
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
	bucket = sourcev1.Bucket{
		ObjectMeta: v1.ObjectMeta{
			Name:      "minio-test-bucket",
			Namespace: "default",
		},
		Spec: sourcev1.BucketSpec{
			BucketName: bucketName,
			Endpoint:   "play.min.io",
			Region:     region,
			Provider:   "generic",
			Insecure:   true,
			SecretRef: &meta.LocalObjectReference{
				Name: secret.Name,
			},
		},
	}
	emptySecret = corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "minio-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{},
		Type: "Opaque",
	}
	bucketNoSecretRef = sourcev1.Bucket{
		ObjectMeta: v1.ObjectMeta{
			Name:      "minio-test-bucket",
			Namespace: "default",
		},
		Spec: sourcev1.BucketSpec{
			BucketName: bucketName,
			Endpoint:   "play.min.io",
			Region:     region,
			Provider:   "generic",
			Insecure:   true,
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
			Region:     region,
			Provider:   "aws",
			Insecure:   true,
		},
	}
)

func TestMain(m *testing.M) {
	var err error
	ctx := context.Background()
	minioclient, err = minio.NewClient(ctx, secret, bucket)
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
	ctx := context.Background()
	minioClient, err := minio.NewClient(ctx, secret, bucket)
	assert.NilError(t, err)
	assert.Assert(t, minioClient != nil)
}

func TestNewClientEmptySecret(t *testing.T) {
	ctx := context.Background()
	minioClient, err := minio.NewClient(ctx, emptySecret, bucket)
	assert.Error(t, err, fmt.Sprintf("invalid '%s' secret data: required fields 'accesskey' and 'secretkey'", emptySecret.Name))
	assert.Assert(t, minioClient == nil)
}

func TestNewClientNoSecretRef(t *testing.T) {
	ctx := context.Background()
	minioClient, err := minio.NewClient(ctx, corev1.Secret{}, bucketNoSecretRef)
	assert.Error(t, err, "no bucket credentials found")
	assert.Assert(t, minioClient == nil)
}

func TestNewClientAwsProvider(t *testing.T) {
	ctx := context.Background()
	minioClient, err := minio.NewClient(ctx, corev1.Secret{}, bucketAwsProvider)
	assert.NilError(t, err)
	assert.Assert(t, minioClient != nil)
}

func TestBucketExists(t *testing.T) {
	ctx := context.Background()
	exists, err := minioclient.BucketExists(ctx, bucketName)
	assert.NilError(t, err)
	assert.Assert(t, exists)
}

func TestBucketNotExists(t *testing.T) {
	ctx := context.Background()
	exists, err := minioclient.BucketExists(ctx, "notexistsbucket")
	assert.NilError(t, err)
	assert.Assert(t, !exists)
}

func TestObjectExists(t *testing.T) {
	ctx := context.Background()
	exists, err := minioclient.ObjectExists(ctx, bucketName, objectName)
	assert.NilError(t, err)
	assert.Assert(t, exists)
}

func TestObjectNotExists(t *testing.T) {
	ctx := context.Background()
	exists, err := minioclient.ObjectExists(ctx, bucketName, "notexists.yaml")
	assert.Error(t, err, "The specified key does not exist.")
	assert.Assert(t, !exists)
}

func TestFGetObject(t *testing.T) {
	ctx := context.Background()
	tempDir, err := os.MkdirTemp("", bucketName)
	assert.NilError(t, err)
	defer os.RemoveAll(tempDir)
	path := filepath.Join(tempDir, sourceignore.IgnoreFile)
	err = minioclient.FGetObject(ctx, bucketName, objectName, path)
	assert.NilError(t, err)
}

func TestListObjects(t *testing.T) {
	ctx := context.Background()
	tempDir, err := os.MkdirTemp("", bucketName)
	assert.NilError(t, err)
	defer os.RemoveAll(tempDir)
	path := filepath.Join(tempDir, sourceignore.IgnoreFile)
	ps, err := sourceignore.ReadIgnoreFile(path, nil)
	assert.NilError(t, err)
	matcher := sourceignore.NewMatcher(ps)
	err = minioclient.ListObjects(ctx, matcher, bucketName, tempDir)
	assert.NilError(t, err)
}

func TestListObjectsErr(t *testing.T) {
	ctx := context.Background()
	badBucketName := "bad-bucket"
	tempDir, err := os.MkdirTemp("", bucketName)
	assert.NilError(t, err)
	defer os.RemoveAll(tempDir)
	path := filepath.Join(tempDir, sourceignore.IgnoreFile)
	ps, err := sourceignore.ReadIgnoreFile(path, nil)
	assert.NilError(t, err)
	matcher := sourceignore.NewMatcher(ps)
	err = minioclient.ListObjects(ctx, matcher, badBucketName, tempDir)
	assert.Error(t, err, fmt.Sprintf("listing objects from bucket '%s' failed: The specified bucket does not exist", badBucketName))
}

func createBucket(ctx context.Context) {
	if err := minioclient.Client.MakeBucket(ctx, bucketName, miniov7.MakeBucketOptions{Region: region}); err != nil {
		exists, errBucketExists := minioclient.BucketExists(ctx, bucketName)
		if errBucketExists == nil && exists {
			deleteBucket(ctx)
		} else {
			log.Fatalln(err)
		}
	}
}

func deleteBucket(ctx context.Context) {
	if err := minioclient.Client.RemoveBucket(ctx, bucketName); err != nil {
		log.Println(err)
	}
}

func addObjectToBucket(ctx context.Context) {
	fileReader := strings.NewReader(getObjectFile())
	fileSize := fileReader.Size()
	_, err := minioclient.Client.PutObject(ctx, bucketName, objectName, fileReader, fileSize, miniov7.PutObjectOptions{
		ContentType: "text/x-yaml",
	})
	if err != nil {
		log.Println(err)
	}
}

func removeObjectFromBucket(ctx context.Context) {
	if err := minioclient.Client.RemoveObject(ctx, bucketName, objectName, miniov7.RemoveObjectOptions{
		GovernanceBypass: true,
	}); err != nil {
		log.Println(err)
	}
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
