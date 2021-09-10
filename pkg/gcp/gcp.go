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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	gcpStorage "cloud.google.com/go/storage"
	interator "google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

const (
	ServiceAccount          = "service_account"
	AuthUri                 = "https://accounts.google.com/o/oauth2/auth"
	TokenUri                = "https://oauth2.googleapis.com/token"
	AuthProviderX509CertUrl = "https://www.googleapis.com/oauth2/v1/certs"
)

var (
	// IteratorDone is returned when the looping of objects/content
	// has reached the end of the iteration.
	IteratorDone = interator.Done
	// ErrorDirectoryExists is an error returned when the filename provided
	// is a directory.
	ErrorDirectoryExists = errors.New("filename is a directory")
	// ErrorObjectDoesNotExist is an error returned when the object whose name
	// is provided does not exist.
	ErrorObjectDoesNotExist = errors.New("object does not exist")
)

type Client interface {
	Bucket(string) *gcpStorage.BucketHandle
	Close() error
}

type BucketHandle interface {
	Create(context.Context, string, *gcpStorage.BucketAttrs) error
	Delete(context.Context) error
	Attrs(context.Context) (*gcpStorage.BucketAttrs, error)
	Object(string) *gcpStorage.ObjectHandle
	Objects(context.Context, *gcpStorage.Query) *gcpStorage.ObjectIterator
}

type ObjectHandle interface {
	Attrs(context.Context) (*gcpStorage.ObjectAttrs, error)
	NewRangeReader(context.Context, int64, int64) (*gcpStorage.Reader, error)
}
type GCPClient struct {
	// client for interacting with the Google Cloud
	// Storage APIs.
	Client Client
	// startRange is the starting read value for
	// reading the object from bucket.
	StartRange int64
	// endRange is the ending read value for
	// reading the object from bucket.
	EndRange int64
}

// CredentialsFile struct representing the GCP Service Account
// JSON file.
type CredentialsFile struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthUri                 string `json:"auth_uri"`
	TokenUri                string `json:"token_uri"`
	AuthProviderX509CertUrl string `json:"auth_provider_x509_cert_url"`
	ClientX509CertUrl       string `json:"client_x509_cert_url"`
}

// NewClient creates a new GCP storage client
// The Google Storage Client will automatically
// look for the Google Application Credential environment variable
// or look for the Google Application Credential file.
func NewClient(ctx context.Context) (*GCPClient, error) {
	client, err := gcpStorage.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	return &GCPClient{Client: client, StartRange: 0, EndRange: -1}, nil
}

// NewClientWithSAKey creates a new GCP storage client
// It uses the provided JSON file with service account details
// To authenticate.
func NewClientWithSAKey(ctx context.Context, credentials *CredentialsFile) (*GCPClient, error) {
	saAccount, err := credentials.credentailsToJSON()
	if err != nil {
		return nil, err
	}

	client, err := gcpStorage.NewClient(ctx, option.WithCredentialsJSON(saAccount))
	if err != nil {
		return nil, err
	}

	return &GCPClient{Client: client, StartRange: 0, EndRange: -1}, nil
}

// credentailsToJSON converts GCP service account credentials struct to JSON.
func (credentials *CredentialsFile) credentailsToJSON() ([]byte, error) {
	credentialsJSON, err := json.Marshal(credentials)
	if err != nil {
		return nil, err
	}

	return credentialsJSON, nil
}

// InitCredentialsWithSecret creates a new credential
// by initializing a new CredentialsFile struct
func InitCredentialsWithSecret(secret map[string][]byte) *CredentialsFile {
	return &CredentialsFile{
		Type:                    ServiceAccount,
		ProjectID:               string(secret["projectid"]),
		PrivateKeyID:            string(secret["privatekeyid"]),
		PrivateKey:              string(secret["privatekey"]),
		ClientEmail:             string(secret["clientemail"]),
		ClientID:                string(secret["clientid"]),
		AuthUri:                 AuthUri,
		TokenUri:                TokenUri,
		AuthProviderX509CertUrl: AuthProviderX509CertUrl,
		ClientX509CertUrl:       string(secret["certurl"]),
	}
}

// ValidateSecret validates the credential secrets
// It ensures that needed secret fields are not missing.
func ValidateSecret(secret map[string][]byte, name string) error {
	if _, exists := secret["projectid"]; !exists {
		return fmt.Errorf("invalid '%s' secret data: required fields 'projectid'", name)
	}
	if _, exists := secret["privatekeyid"]; !exists {
		return fmt.Errorf("invalid '%s' secret data: required fields 'privatekeyid'", name)
	}
	if _, exists := secret["privatekey"]; !exists {
		return fmt.Errorf("invalid '%s' secret data: required fields 'privatekey'", name)
	}
	if _, exists := secret["clientemail"]; !exists {
		return fmt.Errorf("invalid '%s' secret data: required fields 'clientemail'", name)
	}
	if _, exists := secret["clientemail"]; !exists {
		return fmt.Errorf("invalid '%s' secret data: required fields 'clientemail'", name)
	}
	if _, exists := secret["clientid"]; !exists {
		return fmt.Errorf("invalid '%s' secret data: required fields 'clientid'", name)
	}
	if _, exists := secret["certurl"]; !exists {
		return fmt.Errorf("invalid '%s' secret data: required fields 'certurl'", name)
	}

	return nil
}

// SetRange sets the startRange and endRange used to read the Object from
// the bucket. It is a helper method for resumable downloads.
func (c *GCPClient) SetRange(start, end int64) {
	c.StartRange = start
	c.EndRange = end
}

// BucketExists checks if the bucket with the provided name exists.
func (c *GCPClient) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	_, err := c.Client.Bucket(bucketName).Attrs(ctx)
	if err == gcpStorage.ErrBucketNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ObjectAttributes checks if the object with the provided name exists.
// If it exists the Object attributes are returned.
func (c *GCPClient) ObjectAttributes(ctx context.Context, bucketName, objectName string) (bool, *gcpStorage.ObjectAttrs, error) {
	attrs, err := c.Client.Bucket(bucketName).Object(objectName).Attrs(ctx)
	// ErrObjectNotExist is returned if the object does not exist
	if err == gcpStorage.ErrObjectNotExist {
		return false, nil, err
	}
	if err != nil {
		return false, nil, err
	}
	return true, attrs, nil
}

// FGetObject gets the object from the bucket and downloads the object locally
// A part file is created so the download can be resumable.
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
	// Check if the object exists and if you have permission to access it
	// The Object attributes are returned if the Object exists.
	exists, attrs, err := c.ObjectAttributes(ctx, bucketName, objectName)
	if err != nil {
		return err
	}
	if !exists {
		return ErrorObjectDoesNotExist
	}

	// Write to a temporary file "filename.part.gcp" before saving.
	filePartPath := localPath + ".part.gcp"
	// If exists, open in append mode. If not create it as a part file.
	filePart, err := os.OpenFile(filePartPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	// If we return early with an error, be sure to close and delete
	// filePart.  If we have an error along the way there is a chance
	// that filePart is somehow damaged, and we should discard it.
	closeAndRemove := true
	defer func() {
		if closeAndRemove {
			_ = filePart.Close()
			_ = os.Remove(filePartPath)
		}
	}()

	// Issue Stat to get the current offset.
	partFileStat, err := filePart.Stat()
	if err != nil {
		return err
	}

	// Set the File size request range
	// If the part file exists
	if partFileStat.Size() > 0 {
		c.SetRange(partFileStat.Size(), 0)
	}

	// Get Object from GCP Bucket
	objectReader, err := c.Client.Bucket(bucketName).Object(objectName).NewRangeReader(ctx, c.StartRange, c.EndRange)
	if err != nil {
		return err
	}
	defer objectReader.Close()

	// Write to the part file.
	if _, err := io.CopyN(filePart, objectReader, attrs.Size); err != nil {
		return err
	}

	// Close the file before rename, this is specifically needed for Windows users.
	closeAndRemove = false
	if err := filePart.Close(); err != nil {
		return err
	}

	// Safely completed. Now commit by renaming to actual filename.
	if err := os.Rename(filePartPath, localPath); err != nil {
		return err
	}

	return nil
}

// ListObjects lists the objects/contents of the bucket whose bucket name is provided.
// the objects are returned as an Objectiterator and .Next() has to be called on them
// to loop through the Objects.
func (c *GCPClient) ListObjects(ctx context.Context, bucketName string, query *gcpStorage.Query) *gcpStorage.ObjectIterator {
	items := c.Client.Bucket(bucketName).Objects(ctx, query)
	return items
}
