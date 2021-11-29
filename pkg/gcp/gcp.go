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
)

var (
	// IteratorDone is returned when the looping of objects/content
	// has reached the end of the iteration.
	IteratorDone = iterator.Done
	// ErrorDirectoryExists is an error returned when the filename provided
	// is a directory.
	ErrorDirectoryExists = errors.New("filename is a directory")
	// ErrorObjectDoesNotExist is an error returned when the object whose name
	// is provided does not exist.
	ErrorObjectDoesNotExist = errors.New("object does not exist")
)

type GCPClient struct {
	// client for interacting with the Google Cloud
	// Storage APIs.
	*gcpstorage.Client
}

// NewClient creates a new GCP storage client. The Client will automatically look for  the Google Application
// Credential environment variable or look for the Google Application Credential file.
func NewClient(ctx context.Context, opts ...option.ClientOption) (*GCPClient, error) {
	client, err := gcpstorage.NewClient(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return &GCPClient{Client: client}, nil
}

// ValidateSecret validates the credential secrets
// It ensures that needed secret fields are not missing.
func ValidateSecret(secret map[string][]byte, name string) error {
	if _, exists := secret["serviceaccount"]; !exists {
		return fmt.Errorf("invalid '%s' secret data: required fields 'serviceaccount'", name)
	}

	return nil
}

// BucketExists checks if the bucket with the provided name exists.
func (c *GCPClient) BucketExists(ctx context.Context, bucketName string) (bool, error) {
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

// ObjectExists checks if the object with the provided name exists.
func (c *GCPClient) ObjectExists(ctx context.Context, bucketName, objectName string) (bool, error) {
	_, err := c.Client.Bucket(bucketName).Object(objectName).Attrs(ctx)
	// ErrObjectNotExist is returned if the object does not exist
	if err == gcpstorage.ErrObjectNotExist {
		return false, err
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// FGetObject gets the object from the bucket and downloads the object locally
func (c *GCPClient) FGetObject(ctx context.Context, bucketName, objectName, localPath string) error {
	// Verify if destination already exists.
	dirStatus, err := os.Stat(localPath)
	if err == nil {
		// If the destination exists and is a directory.
		if dirStatus.IsDir() {
			return ErrorDirectoryExists
		}
	}

	// Proceed if file does not exist. return for all other errors.
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}

	// Extract top level directory.
	objectDir, _ := filepath.Split(localPath)
	if objectDir != "" {
		// Create any missing top level directories.
		if err := os.MkdirAll(objectDir, 0700); err != nil {
			return err
		}
	}

	// ObjectExists verifies if object exists and you have permission to access.
	// Check if the object exists and if you have permission to access it.
	exists, err := c.ObjectExists(ctx, bucketName, objectName)
	if err != nil {
		return err
	}
	if !exists {
		return ErrorObjectDoesNotExist
	}

	objectFile, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	// Get Object from GCP Bucket
	objectReader, err := c.Client.Bucket(bucketName).Object(objectName).NewReader(ctx)
	if err != nil {
		return err
	}
	defer objectReader.Close()

	// Write Object to file.
	if _, err := io.Copy(objectFile, objectReader); err != nil {
		return err
	}

	// Close the file.
	if err := objectFile.Close(); err != nil {
		return err
	}

	return nil
}

// ListObjects lists the objects/contents of the bucket whose bucket name is provided.
// the objects are returned as an Objectiterator and .Next() has to be called on them
// to loop through the Objects.
func (c *GCPClient) ListObjects(ctx context.Context, bucketName string, query *gcpstorage.Query) *gcpstorage.ObjectIterator {
	items := c.Client.Bucket(bucketName).Objects(ctx, query)
	return items
}

// Close closes the GCP Client and logs any useful errors
func (c *GCPClient) Close(log logr.Logger) {
	if err := c.Client.Close(); err != nil {
		log.Error(err, "GCP Provider")
	}
}
