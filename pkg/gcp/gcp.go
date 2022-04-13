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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	gcpstorage "cloud.google.com/go/storage"
	"github.com/go-logr/logr"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	// IteratorDone is returned when the looping of objects/content
	// has reached the end of the iteration.
	IteratorDone = iterator.Done
	// ErrorDirectoryExists is an error returned when the filename provided
	// is a directory.
	ErrorDirectoryExists = errors.New("filename is a directory")
)

// GCSClient is a minimal Google Cloud Storage client for fetching objects.
type GCSClient struct {
	// client for interacting with the Google Cloud
	// Storage APIs.
	*gcpstorage.Client
}

// NewClient creates a new GCP storage client. The Client will automatically look for  the Google Application
// Credential environment variable or look for the Google Application Credential file.
func NewClient(ctx context.Context, secret *corev1.Secret) (*GCSClient, error) {
	c := &GCSClient{}
	if secret != nil {
		client, err := gcpstorage.NewClient(ctx, option.WithCredentialsJSON(secret.Data["serviceaccount"]))
		if err != nil {
			return nil, err
		}
		c.Client = client
	} else {
		client, err := gcpstorage.NewClient(ctx)
		if err != nil {
			return nil, err
		}
		c.Client = client
	}
	return c, nil
}

// ValidateSecret validates the credential secret. The provided Secret may
// be nil.
func ValidateSecret(secret *corev1.Secret) error {
	if secret == nil {
		return nil
	}
	if _, exists := secret.Data["serviceaccount"]; !exists {
		return fmt.Errorf("invalid '%s' secret data: required fields 'serviceaccount'", secret.Name)
	}
	return nil
}

// BucketExists returns if an object storage bucket with the provided name
// exists, or returns a (client) error.
func (c *GCSClient) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	_, err := c.Client.Bucket(bucketName).Attrs(ctx)
	if err == gcpstorage.ErrBucketNotExist {
		// Not returning error to be compatible with minio's API.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// FGetObject gets the object from the provided object storage bucket, and
// writes it to targetPath.
// It returns the etag of the successfully fetched file, or any error.
func (c *GCSClient) FGetObject(ctx context.Context, bucketName, objectName, localPath string) (string, error) {
	// Verify if destination already exists.
	dirStatus, err := os.Stat(localPath)
	if err == nil {
		// If the destination exists and is a directory.
		if dirStatus.IsDir() {
			return "", ErrorDirectoryExists
		}
	}

	// Proceed if file does not exist. return for all other errors.
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
	}

	// Extract top level directory.
	objectDir, _ := filepath.Split(localPath)
	if objectDir != "" {
		// Create any missing top level directories.
		if err := os.MkdirAll(objectDir, 0o700); err != nil {
			return "", err
		}
	}

	// Get Object attributes.
	objAttr, err := c.Client.Bucket(bucketName).Object(objectName).Attrs(ctx)
	if err != nil {
		return "", err
	}

	// Prepare target file.
	objectFile, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}

	// Get Object data.
	objectReader, err := c.Client.Bucket(bucketName).Object(objectName).If(gcpstorage.Conditions{
		GenerationMatch: objAttr.Generation,
	}).NewReader(ctx)
	if err != nil {
		return "", err
	}
	defer func() {
		if err = objectReader.Close(); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to close object reader")
		}
	}()

	// Write Object to file.
	if _, err := io.Copy(objectFile, objectReader); err != nil {
		return "", err
	}

	// Close the file.
	if err := objectFile.Close(); err != nil {
		return "", err
	}

	return objAttr.Etag, nil
}

// VisitObjects iterates over the items in the provided object storage
// bucket, calling visit for every item.
// If the underlying client or the visit callback returns an error,
// it returns early.
func (c *GCSClient) VisitObjects(ctx context.Context, bucketName string, visit func(path, etag string) error) error {
	items := c.Client.Bucket(bucketName).Objects(ctx, nil)
	for {
		object, err := items.Next()
		if err == IteratorDone {
			break
		}
		if err != nil {
			err = fmt.Errorf("listing objects from bucket '%s' failed: %w", bucketName, err)
			return err
		}
		if err = visit(object.Name, object.Etag); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the GCP Client and logs any useful errors.
func (c *GCSClient) Close(ctx context.Context) {
	log := logr.FromContextOrDiscard(ctx)
	if err := c.Client.Close(); err != nil {
		log.Error(err, "closing GCP client")
	}
}

// ObjectIsNotFound checks if the error provided is storage.ErrObjectNotExist.
func (c *GCSClient) ObjectIsNotFound(err error) bool {
	return errors.Is(err, gcpstorage.ErrObjectNotExist)
}
