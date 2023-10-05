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
	"crypto"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	coptions "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Verifier is an interface for verifying the authenticity of an OCI image.
type Verifier interface {
	Verify(ctx context.Context, ref name.Reference) (bool, error)
}

// options is a struct that holds options for verifier.
type options struct {
	PublicKey  []byte
	ROpt       []remote.Option
	Identities []cosign.Identity
}

// Options is a function that configures the options applied to a Verifier.
type Options func(opts *options)

// WithPublicKey sets the public key.
func WithPublicKey(publicKey []byte) Options {
	return func(opts *options) {
		opts.PublicKey = publicKey
	}
}

// WithRemoteOptions is a functional option for overriding the default
// remote options used by the verifier.
func WithRemoteOptions(opts ...remote.Option) Options {
	return func(o *options) {
		o.ROpt = opts
	}
}

// WithIdentities specifies the identity matchers that have to be met
// for the signature to be deemed valid.
func WithIdentities(identities []cosign.Identity) Options {
	return func(opts *options) {
		opts.Identities = identities
	}
}

// CosignVerifier is a struct which is responsible for executing verification logic.
type CosignVerifier struct {
	opts *cosign.CheckOpts
}

// NewCosignVerifier initializes a new CosignVerifier.
func NewCosignVerifier(ctx context.Context, opts ...Options) (*CosignVerifier, error) {
	o := options{}
	for _, opt := range opts {
		opt(&o)
	}

	checkOpts := &cosign.CheckOpts{}

	ro := coptions.RegistryOptions{}
	co, err := ro.ClientOpts(ctx)
	if err != nil {
		return nil, err
	}

	checkOpts.Identities = o.Identities
	if o.ROpt != nil {
		co = append(co, ociremote.WithRemoteOptions(o.ROpt...))
	}

	checkOpts.RegistryClientOpts = co

	// If a public key is provided, it will use it to verify the signature.
	// If there is no public key provided, it will try keyless verification.
	// https://github.com/sigstore/cosign/blob/main/KEYLESS.md.
	if len(o.PublicKey) > 0 {
		checkOpts.Offline = true
		// TODO(hidde): this is an oversight in our implementation. As it is
		//  theoretically possible to have a custom PK, without disabling tlog.
		checkOpts.IgnoreTlog = true

		pubKeyRaw, err := cryptoutils.UnmarshalPEMToPublicKey(o.PublicKey)
		if err != nil {
			return nil, err
		}

		checkOpts.SigVerifier, err = signature.LoadVerifier(pubKeyRaw, crypto.SHA256)
		if err != nil {
			return nil, err
		}
	} else {
		checkOpts.RekorClient, err = rekor.NewClient(coptions.DefaultRekorURL)
		if err != nil {
			return nil, fmt.Errorf("unable to create Rekor client: %w", err)
		}

		// This performs an online fetch of the Rekor public keys, but this is needed
		// for verifying tlog entries (both online and offline).
		// TODO(hidde): above note is important to keep in mind when we implement
		//  "offline" tlog above.
		if checkOpts.RekorPubKeys, err = cosign.GetRekorPubs(ctx); err != nil {
			return nil, fmt.Errorf("unable to get Rekor public keys: %w", err)
		}

		checkOpts.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get CTLog public keys: %w", err)
		}

		if checkOpts.RootCerts, err = fulcio.GetRoots(); err != nil {
			return nil, fmt.Errorf("unable to get Fulcio root certs: %w", err)
		}

		if checkOpts.IntermediateCerts, err = fulcio.GetIntermediates(); err != nil {
			return nil, fmt.Errorf("unable to get Fulcio intermediate certs: %w", err)
		}
	}

	return &CosignVerifier{
		opts: checkOpts,
	}, nil
}

// VerifyImageSignatures verify the authenticity of the given ref OCI image.
func (v *CosignVerifier) VerifyImageSignatures(ctx context.Context, ref name.Reference) ([]oci.Signature, bool, error) {
	return cosign.VerifyImageSignatures(ctx, ref, v.opts)
}

// Verify verifies the authenticity of the given ref OCI image.
// It returns a boolean indicating if the verification was successful.
// It returns an error if the verification fails, nil otherwise.
func (v *CosignVerifier) Verify(ctx context.Context, ref name.Reference) (bool, error) {
	signatures, _, err := v.VerifyImageSignatures(ctx, ref)
	if err != nil {
		return false, err
	}

	if len(signatures) == 0 {
		return false, nil
	}

	return true, nil
}
