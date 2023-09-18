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
	"fmt"

	"github.com/fluxcd/pkg/oci/auth"
	"github.com/fluxcd/pkg/oci/auth/aws"
	"github.com/fluxcd/pkg/oci/auth/azure"
	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/fluxcd/pkg/cache"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
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

// AuthClient returns a client that can authenticate against an OCI registry.
func AuthClient(provider string, cache *cache.Cache) (auth.Client, error) {
	var client auth.Client
	switch provider {
	case sourcev1.AmazonOCIProvider:
		client = aws.NewClient().WithCache(cache)
	case sourcev1.AzureOCIProvider:
		client = azure.NewClient().WithCache(cache)
	case sourcev1.GoogleOCIProvider:
		client = azure.NewClient().WithCache(cache)
	default:
		return nil, fmt.Errorf("unknown auth provider: %s", provider)
	}
	return client, nil
}
