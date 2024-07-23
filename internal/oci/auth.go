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

package oci

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fluxcd/pkg/cache"
	"github.com/fluxcd/pkg/oci/auth/login"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
)

const (
	// We want to cache the authenticators for the 3rd party providers
	// There are at least 3 providers (aws, azure, gcp), but there could be more
	// e.g. alibaba, ibm, etc. But realistically, we can expect the number of
	// providers to be less than 10.
	DefaultAuthCacheCapacity = 10
	// The cache cleanup interval, to remove expired entries
	// 1 minute is a reasonable interval for authentication tokens.
	// We don't want to be aggressive with the cleanup, as the tokens
	// are valid for a longer period of time usually.
	defaultAuthCacheInterval = time.Minute
)

// Anonymous is an authn.AuthConfig that always returns an anonymous
// authenticator. It is useful for registries that do not require authentication
// or when the credentials are not known.
// It implements authn.Keychain `Resolve` method and can be used as a keychain.
type Anonymous authn.AuthConfig

// Resolve implements authn.Keychain.
func (a Anonymous) Resolve(_ authn.Resource) (authn.Authenticator, error) {
	return authn.Anonymous, nil
}

// OIDCAuthenticatorOptionFunc is a functional option for the OIDCAuthenticator.
type OIDCAuthenticatorOptionFunc func(opts *oidcAuthenticatorOptions)

type oidcAuthenticatorOptions struct {
	capacity int
}

// WithCacheCapacity sets the capacity of the cache.
func WithCacheCapacity(capacity int) OIDCAuthenticatorOptionFunc {
	return func(opts *oidcAuthenticatorOptions) {
		opts.capacity = capacity
	}
}

// OIDCAuthenticator holds a manager for the OIDC authenticators.
// It caches the authenticators to avoid re-authenticating for the same URL.
type OIDCAuthenticator struct {
	manager *login.Manager
	cache   cache.Expirable[cache.StoreObject[authn.Authenticator]]
}

// NewOIDCAuthenticator returns a new OIDCAuthenticator.
// The capacity is the number of authenticators to cache.
// If the capacity is less than or equal to 0, the cache is disabled.
func NewOIDCAuthenticator(opts ...OIDCAuthenticatorOptionFunc) (*OIDCAuthenticator, error) {
	o := &oidcAuthenticatorOptions{}
	for _, opt := range opts {
		opt(o)
	}

	var (
		c   cache.Expirable[cache.StoreObject[authn.Authenticator]]
		err error
	)
	if o.capacity > 0 {
		c, err = cache.New(o.capacity, cache.StoreObjectKeyFunc,
			cache.WithCleanupInterval[cache.StoreObject[authn.Authenticator]](defaultAuthCacheInterval),
			cache.WithMetricsRegisterer[cache.StoreObject[authn.Authenticator]](metrics.Registry))
		if err != nil {
			return nil, fmt.Errorf("failed to create cache: %w", err)
		}
	}

	manager := login.NewManager()
	return &OIDCAuthenticator{cache: c, manager: manager}, nil
}

// Authorization returns an authenticator for the OIDC credentials.
func (o *OIDCAuthenticator) Authorization(ctx context.Context, url, provider string) (authn.Authenticator, error) {
	u := strings.TrimPrefix(url, sourcev1.OCIRepositoryPrefix)
	ref, err := name.ParseReference(u)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL '%s': %w", u, err)
	}

	opts := login.ProviderOptions{Cache: o.cache}
	switch provider {
	case sourcev1.AmazonOCIProvider:
		opts.AwsAutoLogin = true
	case sourcev1.AzureOCIProvider:
		opts.AzureAutoLogin = true
	case sourcev1.GoogleOCIProvider:
		opts.GcpAutoLogin = true
	}

	return o.manager.Login(ctx, u, ref, opts)
}
