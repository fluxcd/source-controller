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

package azure

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	_ "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
)

var (
	// ErrorDirectoryExists is an error returned when the filename provided
	// is a directory.
	ErrorDirectoryExists = errors.New("filename is a directory")
)

const (
	resourceIDField                = "resourceId"
	clientIDField                  = "clientId"
	tenantIDField                  = "tenantId"
	clientSecretField              = "clientSecret"
	clientCertificateField         = "clientCertificate"
	clientCertificatePasswordField = "clientCertificatePassword"
	accountKeyField                = "accountKey"
)

// BlobClient is a minimal Azure Blob client for fetching objects.
type BlobClient struct {
	azblob.ServiceClient
}

// NewClient creates a new Azure Blob storage client.
// The credential config on the client is set based on the data from the
// Bucket and Secret. It detects credentials in the Secret in the following
// order:
//
//  - azidentity.ManagedIdentityCredential for a Resource ID, when a
//   `resourceId` field is found.
//  - azidentity.ManagedIdentityCredential for a User ID, when a `clientId`
//    field but no `tenantId` is found.
//  - azidentity.ClientCertificateCredential when `tenantId`,
//    `clientCertificate` (and optionally `clientCertificatePassword`) fields
//    are found.
//  - azidentity.ClientSecretCredential when `tenantId`, `clientId` and
//    `clientSecret` fields are found.
//	- azblob.SharedKeyCredential when an `accountKey` field is found.
//    The account name is extracted from the endpoint specified on the Bucket
//    object.
//
// If no credentials are found, a simple client without credentials is
// returned.
func NewClient(obj *sourcev1.Bucket, secret *corev1.Secret) (c *BlobClient, err error) {
	c = &BlobClient{}

	// Without a Secret, we can return a simple client.
	if secret == nil || len(secret.Data) == 0 {
		c.ServiceClient, err = azblob.NewServiceClientWithNoCredential(obj.Spec.Endpoint, nil)
		return
	}

	// Attempt AAD Token Credential options first.
	var token azcore.TokenCredential
	if token, err = tokenCredentialFromSecret(secret); err != nil {
		return
	}
	if token != nil {
		c.ServiceClient, err = azblob.NewServiceClient(obj.Spec.Endpoint, token, nil)
		return
	}

	// Fallback to Shared Key Credential.
	cred, err := sharedCredentialFromSecret(obj.Spec.Endpoint, secret)
	if err != nil {
		return
	}
	if cred != nil {
		c.ServiceClient, err = azblob.NewServiceClientWithSharedKey(obj.Spec.Endpoint, cred, &azblob.ClientOptions{})
		return
	}

	// Secret does not contain a valid set of credentials, fallback to simple client.
	c.ServiceClient, err = azblob.NewServiceClientWithNoCredential(obj.Spec.Endpoint, nil)
	return
}

// ValidateSecret validates if the provided Secret does at least have one valid
// set of credentials. The provided Secret may be nil.
func ValidateSecret(secret *corev1.Secret) error {
	if secret == nil {
		return nil
	}

	var valid bool
	if _, hasTenantID := secret.Data[tenantIDField]; hasTenantID {
		if _, hasClientID := secret.Data[clientIDField]; hasClientID {
			if _, hasClientSecret := secret.Data[clientSecretField]; hasClientSecret {
				valid = true
			}
			if _, hasClientCertificate := secret.Data[clientCertificateField]; hasClientCertificate {
				valid = true
			}
		}
	}
	if _, hasResourceID := secret.Data[resourceIDField]; hasResourceID {
		valid = true
	}
	if _, hasClientID := secret.Data[clientIDField]; hasClientID {
		valid = true
	}
	if _, hasAccountKey := secret.Data[accountKeyField]; hasAccountKey {
		valid = true
	}

	if !valid {
		return fmt.Errorf("invalid '%s' secret data: requires a '%s', '%s', or '%s' field, a combination of '%s', '%s' and '%s', or '%s', '%s' and '%s'",
			secret.Name, resourceIDField, clientIDField, accountKeyField, tenantIDField, clientIDField, clientSecretField, tenantIDField, clientIDField, clientCertificateField)
	}
	return nil
}

// BucketExists returns if an object storage bucket with the provided name
// exists, or returns a (client) error.
func (c *BlobClient) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	container := c.ServiceClient.NewContainerClient(bucketName)
	_, err := container.GetProperties(ctx, nil)
	if err != nil {
		var stgErr *azblob.StorageError
		if errors.As(err, &stgErr) {
			if stgErr.ErrorCode == azblob.StorageErrorCodeContainerNotFound {
				return false, nil
			}
			err = stgErr
		}
		return false, err
	}
	return true, nil
}

// FGetObject gets the object from the provided object storage bucket, and
// writes it to targetPath.
// It returns the etag of the successfully fetched file, or any error.
func (c *BlobClient) FGetObject(ctx context.Context, bucketName, objectName, localPath string) (string, error) {
	container := c.ServiceClient.NewContainerClient(bucketName)
	blob := container.NewBlobClient(objectName)

	// Verify if destination already exists.
	dirStatus, err := os.Stat(localPath)
	if err == nil {
		// If the destination exists and is a directory.
		if dirStatus.IsDir() {
			return "", ErrorDirectoryExists
		}
	}

	// Proceed if file does not exist, return for all other errors.
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

	// Download object.
	res, err := blob.Download(ctx, nil)
	if err != nil {
		return "", err
	}

	// Prepare target file.
	f, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}

	// Calculate hash during write.
	// NOTE: not actively used at present, as MD5 is not consistently returned
	// by API.
	hash := md5.New()

	// Off we go.
	mw := io.MultiWriter(f, hash)
	if _, err = io.Copy(mw, res.Body(nil)); err != nil {
		if err = f.Close(); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to close file after copy error")
		}
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return *res.ETag, nil
}

// VisitObjects iterates over the items in the provided object storage
// bucket, calling visit for every item.
// If the underlying client or the visit callback returns an error,
// it returns early.
func (c *BlobClient) VisitObjects(ctx context.Context, bucketName string, visit func(path, etag string) error) error {
	container := c.ServiceClient.NewContainerClient(bucketName)

	items := container.ListBlobsFlat(&azblob.ContainerListBlobFlatSegmentOptions{})
	for items.NextPage(ctx) {
		resp := items.PageResponse()

		for _, blob := range resp.ContainerListBlobFlatSegmentResult.Segment.BlobItems {
			if err := visit(*blob.Name, fmt.Sprintf("%x", *blob.Properties.Etag)); err != nil {
				err = fmt.Errorf("listing objects from bucket '%s' failed: %w", bucketName, err)
				return err
			}
		}
	}
	if err := items.Err(); err != nil {
		err = fmt.Errorf("listing objects from bucket '%s' failed: %w", bucketName, err)
		return err
	}
	return nil
}

// Close has no effect on BlobClient.
func (c *BlobClient) Close(_ context.Context) {
	return
}

// ObjectIsNotFound checks if the error provided is an azblob.StorageError with
// an azblob.StorageErrorCodeBlobNotFound error code.
func (c *BlobClient) ObjectIsNotFound(err error) bool {
	var stgErr *azblob.StorageError
	if errors.As(err, &stgErr) {
		if stgErr.ErrorCode == azblob.StorageErrorCodeBlobNotFound {
			return true
		}
	}
	return false
}

func tokenCredentialFromSecret(secret *corev1.Secret) (azcore.TokenCredential, error) {
	var token azcore.TokenCredential
	if resourceID, ok := secret.Data[resourceIDField]; ok {
		return azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
			ID: azidentity.ResourceID(resourceID),
		})
	}
	if clientID, hasClientID := secret.Data[clientIDField]; hasClientID {
		tenantID, hasTenantID := secret.Data[tenantIDField]
		if !hasTenantID {
			return azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
				ID: azidentity.ClientID(clientID),
			})
		}
		if clientCertificate, hasClientCertificate := secret.Data[clientCertificateField]; hasClientCertificate {
			certs, key, err := azidentity.ParseCertificates(clientCertificate, secret.Data[clientCertificatePasswordField])
			if err != nil {
				return nil, fmt.Errorf("failed to parse client certificates: %w", err)
			}
			return azidentity.NewClientCertificateCredential(string(tenantID), string(clientID), certs, key, nil)
		}
		if clientSecret, hasClientSecret := secret.Data[clientSecretField]; hasClientSecret {
			return azidentity.NewClientSecretCredential(string(tenantID), string(clientID), string(clientSecret), nil)
		}
	}
	return token, nil
}

func sharedCredentialFromSecret(endpoint string, secret *corev1.Secret) (*azblob.SharedKeyCredential, error) {
	if accountKey, hasAccountKey := secret.Data[accountKeyField]; hasAccountKey {
		accountName, err := extractAccountNameFromEndpoint(endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to create shared credential from '%s' Secret data: %w", secret.Name, err)
		}
		return azblob.NewSharedKeyCredential(accountName, string(accountKey))
	}
	return nil, nil
}

// extractAccountNameFromEndpoint extracts the Azure account name from the
// provided endpoint URL. It parses the endpoint as a URL, and returns the
// first subdomain as the assumed account name.
// It returns an error when it fails to parse the endpoint as a URL, or if it
// does not have any subdomains.
func extractAccountNameFromEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("failed to extract account name from endpoint: %w", err)
	}
	hostname := u.Hostname()
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return "", fmt.Errorf("failed to extract account name from endpoint: expected '%s' to be a subdomain", hostname)
	}
	return parts[0], nil
}
