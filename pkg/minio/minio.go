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
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/fluxcd/pkg/runtime/secrets"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
	corev1 "k8s.io/api/core/v1"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
)

// MinioClient is a minimal Minio client for fetching files from S3 compatible
// storage APIs.
type MinioClient struct {
	*minio.Client
}

// options holds the configuration for the Minio client.
type options struct {
	secret       *corev1.Secret
	stsSecret    *corev1.Secret
	tlsConfig    *tls.Config
	stsTLSConfig *tls.Config
	proxyURL     *url.URL
}

// Option is a function that configures the Minio client.
type Option func(*options)

// WithSecret sets the secret for the Minio client.
func WithSecret(secret *corev1.Secret) Option {
	return func(o *options) {
		o.secret = secret
	}
}

// WithTLSConfig sets the TLS configuration for the Minio client.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(o *options) {
		o.tlsConfig = tlsConfig
	}
}

// WithProxyURL sets the proxy URL for the Minio client.
func WithProxyURL(proxyURL *url.URL) Option {
	return func(o *options) {
		o.proxyURL = proxyURL
	}
}

// WithSTSSecret sets the STS secret for the Minio client.
func WithSTSSecret(secret *corev1.Secret) Option {
	return func(o *options) {
		o.stsSecret = secret
	}
}

// WithSTSTLSConfig sets the STS TLS configuration for the Minio client.
func WithSTSTLSConfig(tlsConfig *tls.Config) Option {
	return func(o *options) {
		o.stsTLSConfig = tlsConfig
	}
}

// NewClient creates a new Minio storage client.
func NewClient(bucket *sourcev1.Bucket, opts ...Option) (*MinioClient, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	minioOpts := minio.Options{
		Region: bucket.Spec.Region,
		Secure: !bucket.Spec.Insecure,
		// About BucketLookup, it should be noted that not all S3 providers support
		// path-type access (e.g., Ali OSS). Hence, we revert to using the default
		// auto access, which we believe can cover most use cases.
	}

	switch bucketProvider := bucket.Spec.Provider; {
	case o.secret != nil:
		minioOpts.Creds = newCredsFromSecret(o.secret)
	case bucketProvider == sourcev1.BucketProviderAmazon:
		minioOpts.Creds = newAWSCreds(bucket, o.proxyURL)
	case bucketProvider == sourcev1.BucketProviderGeneric:
		minioOpts.Creds = newGenericCreds(bucket, &o)
	}

	var transportOpts []func(*http.Transport)

	if minioOpts.Secure && o.tlsConfig != nil {
		transportOpts = append(transportOpts, func(t *http.Transport) {
			t.TLSClientConfig = o.tlsConfig.Clone()
		})
	}

	if o.proxyURL != nil {
		transportOpts = append(transportOpts, func(t *http.Transport) {
			t.Proxy = http.ProxyURL(o.proxyURL)
		})
	}

	if len(transportOpts) > 0 {
		transport, err := minio.DefaultTransport(minioOpts.Secure)
		if err != nil {
			return nil, fmt.Errorf("failed to create default minio transport: %w", err)
		}
		for _, opt := range transportOpts {
			opt(transport)
		}
		minioOpts.Transport = transport
	}

	client, err := minio.New(bucket.Spec.Endpoint, &minioOpts)
	if err != nil {
		return nil, err
	}
	return &MinioClient{Client: client}, nil
}

// newCredsFromSecret creates a new Minio credentials object from the provided
// secret.
func newCredsFromSecret(secret *corev1.Secret) *credentials.Credentials {
	var accessKey, secretKey string
	if k, ok := secret.Data["accesskey"]; ok {
		accessKey = string(k)
	}
	if k, ok := secret.Data["secretkey"]; ok {
		secretKey = string(k)
	}
	if accessKey != "" && secretKey != "" {
		return credentials.NewStaticV4(accessKey, secretKey, "")
	}
	return nil
}

// newAWSCreds creates a new Minio credentials object for `aws` bucket provider.
func newAWSCreds(bucket *sourcev1.Bucket, proxyURL *url.URL) *credentials.Credentials {
	stsEndpoint := ""
	if sts := bucket.Spec.STS; sts != nil {
		stsEndpoint = sts.Endpoint
	}

	creds := credentials.NewIAM(stsEndpoint)
	if proxyURL != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = http.ProxyURL(proxyURL)
		client := &http.Client{Transport: transport}
		creds = credentials.New(&credentials.IAM{
			Client:   client,
			Endpoint: stsEndpoint,
		})
	}
	return creds
}

// newGenericCreds creates a new Minio credentials object for the `generic` bucket provider.
func newGenericCreds(bucket *sourcev1.Bucket, o *options) *credentials.Credentials {

	sts := bucket.Spec.STS
	if sts == nil {
		return nil
	}

	switch sts.Provider {
	case sourcev1.STSProviderLDAP:
		client := &http.Client{Transport: http.DefaultTransport}
		if o.proxyURL != nil || o.stsTLSConfig != nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			if o.proxyURL != nil {
				transport.Proxy = http.ProxyURL(o.proxyURL)
			}
			if o.stsTLSConfig != nil {
				transport.TLSClientConfig = o.stsTLSConfig.Clone()
			}
			client = &http.Client{Transport: transport}
		}
		var username, password string
		if o.stsSecret != nil {
			username = string(o.stsSecret.Data["username"])
			password = string(o.stsSecret.Data["password"])
		}
		return credentials.New(&credentials.LDAPIdentity{
			Client:       client,
			STSEndpoint:  sts.Endpoint,
			LDAPUsername: username,
			LDAPPassword: password,
		})
	}

	return nil
}

// ValidateSecret validates the credential secret. The provided Secret may
// be nil.
func ValidateSecret(secret *corev1.Secret) error {
	if secret == nil {
		return nil
	}
	if _, ok := secret.Data["accesskey"]; !ok {
		return &secrets.KeyNotFoundError{Key: "accesskey", Secret: secret}
	}
	if _, ok := secret.Data["secretkey"]; !ok {
		return &secrets.KeyNotFoundError{Key: "secretkey", Secret: secret}
	}
	return nil
}

// ValidateSTSProvider validates the STS provider.
func ValidateSTSProvider(bucketProvider string, sts *sourcev1.BucketSTSSpec) error {
	errProviderIncompatbility := fmt.Errorf("STS provider '%s' is not supported for '%s' bucket provider",
		sts.Provider, bucketProvider)
	errSecretNotRequired := fmt.Errorf("spec.sts.secretRef is not required for the '%s' STS provider",
		sts.Provider)
	errCertSecretNotRequired := fmt.Errorf("spec.sts.certSecretRef is not required for the '%s' STS provider",
		sts.Provider)

	switch bucketProvider {
	case sourcev1.BucketProviderAmazon:
		switch sts.Provider {
		case sourcev1.STSProviderAmazon:
			if sts.SecretRef != nil {
				return errSecretNotRequired
			}
			if sts.CertSecretRef != nil {
				return errCertSecretNotRequired
			}
			return nil
		default:
			return errProviderIncompatbility
		}
	case sourcev1.BucketProviderGeneric:
		switch sts.Provider {
		case sourcev1.STSProviderLDAP:
			return nil
		default:
			return errProviderIncompatbility
		}
	}

	return fmt.Errorf("STS configuration is not supported for '%s' bucket provider", bucketProvider)
}

// ValidateSTSSecret validates the STS secret. The provided Secret may be nil.
func ValidateSTSSecret(stsProvider string, secret *corev1.Secret) error {
	switch stsProvider {
	case sourcev1.STSProviderLDAP:
		return validateSTSSecretForProvider(stsProvider, secret, "username", "password")
	default:
		return nil
	}
}

// validateSTSSecretForProvider validates the STS secret for each provider.
// The provided Secret may be nil.
func validateSTSSecretForProvider(stsProvider string, secret *corev1.Secret, keys ...string) error {
	if secret == nil {
		return nil
	}
	if len(secret.Data) == 0 && len(keys) > 0 {
		return &secrets.KeyNotFoundError{Key: keys[0], Secret: secret}
	}
	for _, key := range keys {
		value, ok := secret.Data[key]
		if !ok || len(value) == 0 {
			return &secrets.KeyNotFoundError{Key: key, Secret: secret}
		}
	}
	return nil
}

// FGetObject gets the object from the provided object storage bucket, and
// writes it to targetPath.
// It returns the etag of the successfully fetched file, or any error.
func (c *MinioClient) FGetObject(ctx context.Context, bucketName, objectName, localPath string) (string, error) {
	stat, err := c.Client.StatObject(ctx, bucketName, objectName, minio.GetObjectOptions{})
	if err != nil {
		return "", err
	}
	opts := minio.GetObjectOptions{}
	if err = opts.SetMatchETag(stat.ETag); err != nil {
		return "", err
	}
	if err = c.Client.FGetObject(ctx, bucketName, objectName, localPath, opts); err != nil {
		return "", err
	}
	return stat.ETag, nil
}

// VisitObjects iterates over the items in the provided object storage
// bucket, calling visit for every item.
// If the underlying client or the visit callback returns an error,
// it returns early.
func (c *MinioClient) VisitObjects(ctx context.Context, bucketName string, prefix string, visit func(key, etag string) error) error {
	for object := range c.Client.ListObjects(ctx, bucketName, minio.ListObjectsOptions{
		Recursive: true,
		Prefix:    prefix,
		UseV1:     s3utils.IsGoogleEndpoint(*c.Client.EndpointURL()),
	}) {
		if object.Err != nil {
			err := fmt.Errorf("listing objects from bucket '%s' failed: %w", bucketName, object.Err)
			return err
		}

		if err := visit(object.Key, object.ETag); err != nil {
			return err
		}
	}
	return nil
}

// ObjectIsNotFound checks if the error provided is a minio.ErrResponse
// with "NoSuchKey" code.
func (c *MinioClient) ObjectIsNotFound(err error) bool {
	if resp := new(minio.ErrorResponse); errors.As(err, resp) {
		return resp.Code == "NoSuchKey"
	}
	return false
}

// Close closes the Minio Client and logs any useful errors.
func (c *MinioClient) Close(_ context.Context) {
	// Minio client does not provide a close method
}
