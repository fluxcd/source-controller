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

package minio

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/pkg/sourceignore"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
	corev1 "k8s.io/api/core/v1"
)

type MinioClient struct {
	// client for interacting with S3 compatible
	// Storage APIs.
	*minio.Client
}

// NewClient creates a new Minio storage client.
func NewClient(ctx context.Context, secret corev1.Secret, bucket sourcev1.Bucket) (*MinioClient, error) {
	opt := minio.Options{
		Region: bucket.Spec.Region,
		Secure: !bucket.Spec.Insecure,
	}

	if bucket.Spec.SecretRef != nil {
		accesskey := ""
		secretkey := ""
		if k, ok := secret.Data["accesskey"]; ok {
			accesskey = string(k)
		}
		if k, ok := secret.Data["secretkey"]; ok {
			secretkey = string(k)
		}
		if accesskey == "" || secretkey == "" {
			return nil, fmt.Errorf("invalid '%s' secret data: required fields 'accesskey' and 'secretkey'", secret.Name)
		}
		opt.Creds = credentials.NewStaticV4(accesskey, secretkey, "")
	} else if bucket.Spec.Provider == sourcev1.AmazonBucketProvider {
		opt.Creds = credentials.NewIAM("")
	}

	if opt.Creds == nil {
		return nil, fmt.Errorf("no bucket credentials found")
	}

	client, err := minio.New(bucket.Spec.Endpoint, &opt)
	if err != nil {
		return nil, err
	}

	return &MinioClient{Client: client}, nil
}

// BucketExists checks if the bucket with the provided name exists.
func (c *MinioClient) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	return c.Client.BucketExists(ctx, bucketName)
}

// ObjectExists checks if the object with the provided name exists.
func (c *MinioClient) ObjectExists(ctx context.Context, bucketName, objectName string) (bool, error) {
	_, err := c.Client.StatObject(ctx, bucketName, objectName, minio.StatObjectOptions{})
	if err != nil {
		return false, err
	}
	return true, nil
}

// FGetObject gets the object from the bucket and downloads the object locally.
func (c *MinioClient) FGetObject(ctx context.Context, bucketName, objectName, localPath string) error {
	return c.Client.FGetObject(ctx, bucketName, objectName, localPath, minio.GetObjectOptions{})
}

// ListObjects lists all the objects in a bucket and downloads the objects.
func (c *MinioClient) ListObjects(ctx context.Context, matcher gitignore.Matcher, bucketName, tempDir string) error {
	for object := range c.Client.ListObjects(ctx, bucketName, minio.ListObjectsOptions{
		Recursive: true,
		UseV1:     s3utils.IsGoogleEndpoint(*c.Client.EndpointURL()),
	}) {
		if object.Err != nil {
			err := fmt.Errorf("listing objects from bucket '%s' failed: %w", bucketName, object.Err)
			return err
		}

		if strings.HasSuffix(object.Key, "/") || object.Key == sourceignore.IgnoreFile {
			continue
		}

		if matcher.Match(strings.Split(object.Key, "/"), false) {
			continue
		}

		localPath := filepath.Join(tempDir, object.Key)
		err := c.FGetObject(ctx, bucketName, object.Key, localPath)
		if err != nil {
			err = fmt.Errorf("downloading object from bucket '%s' failed: %w", bucketName, err)
			return err
		}
	}
	return nil
}

// Close closes the Minio Client and logs any useful errors
func (c *MinioClient) Close(ctx context.Context) {
	//minio client does not provide a close method
}
