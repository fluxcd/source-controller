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
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	gcpstorage "cloud.google.com/go/storage"
	"github.com/go-logr/logr"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	htransport "google.golang.org/api/transport/http"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/fluxcd/pkg/auth"
	gcpauth "github.com/fluxcd/pkg/auth/gcp"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
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

// Option is a functional option for configuring the GCS client.
type Option func(*options)

// WithSecret sets the secret to use for authenticating with GCP.
func WithSecret(secret *corev1.Secret) Option {
	return func(o *options) {
		o.secret = secret
	}
}

// WithProxyURL sets the proxy URL to use for the GCS client.
func WithProxyURL(proxyURL *url.URL) Option {
	return func(o *options) {
		o.proxyURL = proxyURL
	}
}

// WithAuth sets the auth options for workload identity authentication.
func WithAuth(authOpts ...auth.Option) Option {
	return func(o *options) {
		o.authOpts = authOpts
	}
}

type options struct {
	secret   *corev1.Secret
	proxyURL *url.URL
	authOpts []auth.Option

	// newCustomHTTPClient should create a new HTTP client for interacting with the GCS API.
	// This is a test-only option required for mocking the real logic, which requires either
	// a valid Google Service Account Key or Controller-Level Workload Identity. Both are not available in tests.
	// The real logic is implemented in the newHTTPClient function, which is used when
	// constructing the default options object.
	newCustomHTTPClient func(context.Context, *options) (*http.Client, error)
}

func newOptions() *options {
	return &options{
		newCustomHTTPClient: newHTTPClient,
	}
}

// NewClient creates a new GCP storage client. The Client will automatically look for the Google Application
// Credential environment variable or look for the Google Application Credential file.
func NewClient(ctx context.Context, bucket *sourcev1.Bucket, opts ...Option) (*GCSClient, error) {
	o := newOptions()
	for _, opt := range opts {
		opt(o)
	}

	var clientOpts []option.ClientOption

	switch {
	case o.secret != nil && o.proxyURL == nil:
		clientOpts = append(clientOpts, option.WithCredentialsJSON(o.secret.Data["serviceaccount"]))
	case o.secret == nil && o.proxyURL == nil:
		tokenSource := gcpauth.NewTokenSource(ctx, o.authOpts...)
		clientOpts = append(clientOpts, option.WithTokenSource(tokenSource))
	default: // o.proxyURL != nil:
		httpClient, err := o.newCustomHTTPClient(ctx, o)
		if err != nil {
			return nil, err
		}
		clientOpts = append(clientOpts, option.WithHTTPClient(httpClient))
	}

	client, err := gcpstorage.NewClient(ctx, clientOpts...)
	if err != nil {
		return nil, err
	}

	return &GCSClient{client}, nil
}

// newHTTPClient creates a new HTTP client for interacting with Google Cloud APIs.
func newHTTPClient(ctx context.Context, o *options) (*http.Client, error) {
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	if o.proxyURL != nil {
		baseTransport.Proxy = http.ProxyURL(o.proxyURL)
	}

	var opts []option.ClientOption

	if o.secret != nil {
		// Here we can't use option.WithCredentialsJSON() because htransport.NewTransport()
		// won't know what scopes to use and yield a 400 Bad Request error when retrieving
		// the OAuth token. Instead we use google.CredentialsFromJSON(), which allows us to
		// specify the GCS read-only scope.
		creds, err := google.CredentialsFromJSON(ctx, o.secret.Data["serviceaccount"], gcpstorage.ScopeReadOnly)
		if err != nil {
			return nil, fmt.Errorf("failed to create Google credentials from secret: %w", err)
		}
		opts = append(opts, option.WithCredentials(creds))
	} else { // Workload Identity.
		tokenSource := gcpauth.NewTokenSource(ctx, o.authOpts...)
		opts = append(opts, option.WithTokenSource(tokenSource))
	}

	transport, err := htransport.NewTransport(ctx, baseTransport, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Google HTTP transport: %w", err)
	}
	return &http.Client{Transport: transport}, nil
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
	if err == nil {
		return true, nil
	}
	if errors.Is(err, gcpstorage.ErrBucketNotExist) {
		// Not returning error to be compatible with minio's API.
		return false, nil
	}
	return false, err
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
func (c *GCSClient) VisitObjects(ctx context.Context, bucketName string, prefix string, visit func(path, etag string) error) error {
	items := c.Client.Bucket(bucketName).Objects(ctx, &gcpstorage.Query{
		Prefix: prefix,
	})
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
