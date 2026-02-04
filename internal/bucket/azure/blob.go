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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/fluxcd/pkg/auth"
	azureauth "github.com/fluxcd/pkg/auth/azure"
	"github.com/fluxcd/pkg/masktoken"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
)

var (
	// ErrorDirectoryExists is an error returned when the filename provided
	// is a directory.
	ErrorDirectoryExists = errors.New("filename is a directory")
)

const (
	clientIDField                   = "clientId"
	tenantIDField                   = "tenantId"
	clientSecretField               = "clientSecret"
	clientCertificateField          = "clientCertificate"
	clientCertificatePasswordField  = "clientCertificatePassword"
	clientCertificateSendChainField = "clientCertificateSendChain"
	authorityHostField              = "authorityHost"
	accountKeyField                 = "accountKey"
	sasKeyField                     = "sasKey"
)

// BlobClient is a minimal Azure Blob client for fetching objects.
type BlobClient struct {
	*azblob.Client
}

// Option configures the BlobClient.
type Option func(*options)

// WithSecret sets the Secret to use for the BlobClient.
func WithSecret(secret *corev1.Secret) Option {
	return func(o *options) {
		o.secret = secret
	}
}

// WithProxyURL sets the proxy URL to use for the BlobClient.
func WithProxyURL(proxyURL *url.URL) Option {
	return func(o *options) {
		o.proxyURL = proxyURL
	}
}

type options struct {
	secret             *corev1.Secret
	proxyURL           *url.URL
	withoutCredentials bool
	withoutRetries     bool
	authOpts           []auth.Option
}

// withoutCredentials forces the BlobClient to not use any credentials.
// This is a test-only option useful for testing the client with HTTP
// endpoints (without TLS) alongside all the other options unrelated to
// credentials.
func withoutCredentials() Option {
	return func(o *options) {
		o.withoutCredentials = true
	}
}

// withoutRetries sets the BlobClient to not retry requests.
// This is a test-only option useful for testing connection errors.
func withoutRetries() Option {
	return func(o *options) {
		o.withoutRetries = true
	}
}

// WithAuth sets the auth options for workload identity authentication.
func WithAuth(authOpts ...auth.Option) Option {
	return func(o *options) {
		o.authOpts = authOpts
	}
}

// NewClient creates a new Azure Blob storage client.
// The credential config on the client is set based on the data from the
// Bucket and Secret. It detects credentials in the Secret in the following
// order:
//
//   - azidentity.ClientSecretCredential when `tenantId`, `clientId` and
//     `clientSecret` fields are found.
//   - azidentity.ClientCertificateCredential when `tenantId`,
//     `clientCertificate` (and optionally `clientCertificatePassword`) fields
//     are found.
//   - azidentity.ManagedIdentityCredential for a User ID, when a `clientId`
//     field but no `tenantId` is found.
//   - azidentity.WorkloadIdentityCredential for when environment variables
//     (AZURE_AUTHORITY_HOST, AZURE_CLIENT_ID, AZURE_FEDERATED_TOKEN_FILE, AZURE_TENANT_ID)
//     are set by the Azure workload identity webhook.
//   - azblob.SharedKeyCredential when an `accountKey` field is found.
//     The account name is extracted from the endpoint specified on the Bucket
//     object.
//   - azidentity.ChainedTokenCredential with azidentity.EnvironmentCredential
//     and azidentity.ManagedIdentityCredential.
//
// If no credentials are found, and the azidentity.ChainedTokenCredential can
// not be established. A simple client without credentials is returned.
func NewClient(ctx context.Context, obj *sourcev1.Bucket, opts ...Option) (c *BlobClient, err error) {
	c = &BlobClient{}

	var o options
	for _, opt := range opts {
		opt(&o)
	}

	clientOpts := &azblob.ClientOptions{}

	if o.proxyURL != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = http.ProxyURL(o.proxyURL)
		clientOpts.ClientOptions.Transport = &http.Client{Transport: transport}
	}

	if o.withoutRetries {
		clientOpts.ClientOptions.Retry.ShouldRetry = func(resp *http.Response, err error) bool {
			return false
		}
	}

	if o.withoutCredentials {
		c.Client, err = azblob.NewClientWithNoCredential(obj.Spec.Endpoint, clientOpts)
		return
	}

	var token azcore.TokenCredential

	if o.secret != nil && len(o.secret.Data) > 0 {
		// Attempt AAD Token Credential options first.
		if token, err = tokenCredentialFromSecret(o.secret); err != nil {
			err = fmt.Errorf("failed to create token credential from '%s' Secret: %w", o.secret.Name, err)
			return
		}
		if token != nil {
			c.Client, err = azblob.NewClient(obj.Spec.Endpoint, token, clientOpts)
			return
		}

		// Fallback to Shared Key Credential.
		var cred *azblob.SharedKeyCredential
		if cred, err = sharedCredentialFromSecret(obj.Spec.Endpoint, o.secret); err != nil {
			return
		}
		if cred != nil {
			c.Client, err = azblob.NewClientWithSharedKeyCredential(obj.Spec.Endpoint, cred, clientOpts)
			return
		}

		var fullPath string
		if fullPath, err = sasTokenFromSecret(obj.Spec.Endpoint, o.secret); err != nil {
			return
		}

		c.Client, err = azblob.NewClientWithNoCredential(fullPath, clientOpts)
		return
	}

	// Compose token chain based on environment.
	// This functions as a replacement for azidentity.NewDefaultAzureCredential
	// to not shell out.
	token, err = chainCredentialWithSecret(ctx, o.secret, o.authOpts...)
	if err != nil {
		err = fmt.Errorf("failed to create environment credential chain: %w", err)
		return nil, err
	}
	if token != nil {
		c.Client, err = azblob.NewClient(obj.Spec.Endpoint, token, clientOpts)
		return
	}

	// Fallback to simple client.
	c.Client, err = azblob.NewClientWithNoCredential(obj.Spec.Endpoint, clientOpts)
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
	if _, hasClientID := secret.Data[clientIDField]; hasClientID {
		valid = true
	}
	if _, hasAccountKey := secret.Data[accountKeyField]; hasAccountKey {
		valid = true
	}
	if _, hasSasKey := secret.Data[sasKeyField]; hasSasKey {
		valid = true
	}
	if _, hasAuthorityHost := secret.Data[authorityHostField]; hasAuthorityHost {
		valid = true
	}

	if !valid {
		return fmt.Errorf("invalid '%s' secret data: requires a '%s' or '%s' field, a combination of '%s', '%s' and '%s', or '%s', '%s' and '%s'",
			secret.Name, clientIDField, accountKeyField, tenantIDField, clientIDField, clientSecretField, tenantIDField, clientIDField, clientCertificateField)
	}
	return nil
}

// BucketExists returns if an object storage bucket with the provided name
// exists, or returns a (client) error.
func (c *BlobClient) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	items := c.Client.NewListBlobsFlatPager(bucketName, &azblob.ListBlobsFlatOptions{
		MaxResults: to.Ptr(int32(1)),
	})
	// We call next page only once since we just want to see if we get an error
	if _, err := items.NextPage(ctx); err != nil {
		if bloberror.HasCode(err, bloberror.ContainerNotFound) {
			return false, nil
		}

		// For a container-level SASToken, we get an AuthenticationFailed when the bucket doesn't exist
		if bloberror.HasCode(err, bloberror.AuthenticationFailed) {
			return false, fmt.Errorf("the specified bucket name may be incorrect, nonexistent, or the caller might lack sufficient permissions to access it: %w", err)
		}

		return false, err
	}
	return true, nil
}

// FGetObject gets the object from the provided object storage bucket, and
// writes it to targetPath.
// It returns the etag of the successfully fetched file, or any error.
func (c *BlobClient) FGetObject(ctx context.Context, bucketName, objectName, localPath string) (string, error) {
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
	res, err := c.DownloadStream(ctx, bucketName, objectName, nil)
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
	if _, err = io.Copy(mw, res.Body); err != nil {
		if err = f.Close(); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to close file after copy error")
		}
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}

	return string(*res.ETag), nil
}

// VisitObjects iterates over the items in the provided object storage
// bucket, calling visit for every item.
// If the underlying client or the visit callback returns an error,
// it returns early.
func (c *BlobClient) VisitObjects(ctx context.Context, bucketName string, prefix string, visit func(path, etag string) error) error {
	items := c.NewListBlobsFlatPager(bucketName, nil)
	for items.More() {
		resp, err := items.NextPage(ctx)
		if err != nil {
			err = fmt.Errorf("listing objects from bucket '%s' failed: %w", bucketName, err)
			return err
		}
		for _, blob := range resp.Segment.BlobItems {
			if err := visit(*blob.Name, fmt.Sprintf("%x", *blob.Properties.ETag)); err != nil {
				err = fmt.Errorf("listing objects from bucket '%s' failed: %w", bucketName, err)
				return err
			}
		}
	}

	return nil
}

// Close has no effect on BlobClient.
func (c *BlobClient) Close(_ context.Context) {}

// ObjectIsNotFound checks if the error provided is an azblob.StorageError with
// an azblob.StorageErrorCodeBlobNotFound error code.
func (c *BlobClient) ObjectIsNotFound(err error) bool {
	return bloberror.HasCode(err, bloberror.BlobNotFound)
}

// tokenCredentialsFromSecret attempts to create an azcore.TokenCredential
// based on the data fields of the given Secret. It returns, in order:
//   - azidentity.ClientSecretCredential when `tenantId`, `clientId` and
//     `clientSecret` fields are found.
//   - azidentity.ClientCertificateCredential when `tenantId`,
//     `clientCertificate` (and optionally `clientCertificatePassword`) fields
//     are found.
//   - azidentity.ManagedIdentityCredential for a User ID, when a `clientId`
//     field but no `tenantId` is found.
//   - Nil, if no valid set of credential fields was found.
func tokenCredentialFromSecret(secret *corev1.Secret) (azcore.TokenCredential, error) {
	if secret == nil {
		return nil, nil
	}

	clientID, hasClientID := secret.Data[clientIDField]
	if tenantID, hasTenantID := secret.Data[tenantIDField]; hasTenantID && hasClientID {
		if clientSecret, hasClientSecret := secret.Data[clientSecretField]; hasClientSecret && len(clientSecret) > 0 {
			opts := &azidentity.ClientSecretCredentialOptions{}
			if authorityHost, hasAuthorityHost := secret.Data[authorityHostField]; hasAuthorityHost {
				opts.Cloud = cloud.Configuration{ActiveDirectoryAuthorityHost: string(authorityHost)}
			}
			return azidentity.NewClientSecretCredential(string(tenantID), string(clientID), string(clientSecret), opts)
		}
		if clientCertificate, hasClientCertificate := secret.Data[clientCertificateField]; hasClientCertificate && len(clientCertificate) > 0 {
			certs, key, err := azidentity.ParseCertificates(clientCertificate, secret.Data[clientCertificatePasswordField])
			if err != nil {
				return nil, fmt.Errorf("failed to parse client certificates: %w", err)
			}
			opts := &azidentity.ClientCertificateCredentialOptions{}
			if authorityHost, hasAuthorityHost := secret.Data[authorityHostField]; hasAuthorityHost {
				opts.Cloud = cloud.Configuration{ActiveDirectoryAuthorityHost: string(authorityHost)}
			}
			if v, sendChain := secret.Data[clientCertificateSendChainField]; sendChain {
				opts.SendCertificateChain = string(v) == "1" || strings.ToLower(string(v)) == "true"
			}
			return azidentity.NewClientCertificateCredential(string(tenantID), string(clientID), certs, key, opts)
		}
	}
	if hasClientID {
		return azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
			ID: azidentity.ClientID(clientID),
		})
	}
	return nil, nil
}

// sharedCredentialFromSecret attempts to create an azblob.SharedKeyCredential
// based on the data fields of the given Secret. It returns nil if the Secret
// does not contain a valid set of credentials.
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

// sasTokenFromSecret retrieves the SAS Token from the `sasKey`. It returns an empty string if the Secret
// does not contain a valid set of credentials.
func sasTokenFromSecret(ep string, secret *corev1.Secret) (string, error) {
	if sasKey, hasSASKey := secret.Data[sasKeyField]; hasSASKey {
		queryString := strings.TrimPrefix(string(sasKey), "?")
		values, err := url.ParseQuery(queryString)
		if err != nil {
			maskedErrorString, maskErr := masktoken.MaskTokenFromString(err.Error(), string(sasKey))
			if maskErr != nil {
				return "", fmt.Errorf("error redacting token from error message: %s", maskErr)
			}
			return "", fmt.Errorf("unable to parse SAS token: %s", maskedErrorString)
		}

		epURL, err := url.Parse(ep)
		if err != nil {
			return "", fmt.Errorf("unable to parse endpoint URL: %s", err)
		}

		//merge the query values in the endpoint with the token
		epValues := epURL.Query()
		for key, val := range epValues {
			if !values.Has(key) {
				for _, str := range val {
					values.Add(key, str)
				}
			}
		}

		epURL.RawQuery = values.Encode()
		return epURL.String(), nil
	}
	return "", nil
}

// chainCredentialWithSecret tries to create a set of tokens, and returns an
// azidentity.ChainedTokenCredential if at least one of the following tokens was
// successfully created:
//
//   - azidentity.EnvironmentCredential with `authorityHost` from Secret, if
//     provided.
//   - azidentity.WorkloadIdentityCredential with Client ID from AZURE_CLIENT_ID plus
//     AZURE_TENANT_ID, AZURE_FEDERATED_TOKEN_FILE from environment variables
//     environment variable, if found.
//   - azidentity.ManagedIdentityCredential with Client ID from AZURE_CLIENT_ID
//     environment variable, if found.
//   - azidentity.ManagedIdentityCredential with defaults.
//
// If no valid token is created, it returns nil.
func chainCredentialWithSecret(ctx context.Context, secret *corev1.Secret, opts ...auth.Option) (azcore.TokenCredential, error) {
	var creds []azcore.TokenCredential

	credOpts := &azidentity.EnvironmentCredentialOptions{}
	if secret != nil {
		if authorityHost, hasAuthorityHost := secret.Data[authorityHostField]; hasAuthorityHost {
			credOpts.Cloud = cloud.Configuration{ActiveDirectoryAuthorityHost: string(authorityHost)}
		}
	}

	if token, _ := azidentity.NewEnvironmentCredential(credOpts); token != nil {
		creds = append(creds, token)
	}
	if token := azureauth.NewTokenCredential(ctx, opts...); token != nil {
		creds = append(creds, token)
	}

	if len(creds) > 0 {
		return azidentity.NewChainedTokenCredential(creds, nil)
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
