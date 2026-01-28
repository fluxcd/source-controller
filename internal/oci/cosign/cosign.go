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

package cosign

import (
	"context"
	"crypto"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio"
	coptions "github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"

	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	soci "github.com/fluxcd/source-controller/internal/oci"
)

// options is a struct that holds options for verifier.
type options struct {
	publicKey  []byte
	rOpt       []remote.Option
	identities []cosign.Identity
}

// Options is a function that configures the options applied to a Verifier.
type Options func(opts *options)

// WithPublicKey sets the public key.
func WithPublicKey(publicKey []byte) Options {
	return func(opts *options) {
		opts.publicKey = publicKey
	}
}

// WithRemoteOptions is a functional option for overriding the default
// remote options used by the verifier.
func WithRemoteOptions(opts ...remote.Option) Options {
	return func(o *options) {
		o.rOpt = opts
	}
}

// WithIdentities specifies the identity matchers that have to be met
// for the signature to be deemed valid.
func WithIdentities(identities []cosign.Identity) Options {
	return func(opts *options) {
		opts.identities = identities
	}
}

// CosignVerifier is a struct which is responsible for executing verification logic.
type CosignVerifier struct {
	opts *cosign.CheckOpts
}

// CosignVerifierFactory is a factory for creating Verifiers with shared state.
// A mutex is used to ensure a TUF trustedRoot is initialized and shared for all
// NewCosignVerifier's. In the event that a trustedRoot can't be initialized, the
// factory rate-limits creation based on an internal retryInterval.
// Only the v3/bundle compatible trustedRoot is shared by the factory.
// Keys for v2 retain the behavior from previous versions of Flux.
type CosignVerifierFactory struct {
	trustedMaterial root.TrustedMaterial
	mu              sync.Mutex
	initErr         error
	lastAttempt     time.Time
	retryInterval   time.Duration
}

// NewCosignVerifierFactory initializes a new CosignVerifierFactory.
// TrustedRoot creation attempts are rate-limited to every minute.
func NewCosignVerifierFactory() *CosignVerifierFactory {
	return &CosignVerifierFactory{
		retryInterval: time.Minute,
	}
}

// NewCosignVerifier initializes a new CosignVerifier using the factory's shared state.
func (f *CosignVerifierFactory) NewCosignVerifier(ctx context.Context, opts ...Options) (*CosignVerifier, error) {
	o := options{}
	for _, opt := range opts {
		opt(&o)
	}

	checkOpts := &cosign.CheckOpts{}
	// enable bundles by default -- this is the future direction of cosign
	checkOpts.NewBundleFormat = true

	ro := coptions.RegistryOptions{}
	co, err := ro.ClientOpts(ctx)
	if err != nil {
		return nil, err
	}

	checkOpts.Identities = o.identities
	if o.rOpt != nil {
		co = append(co, ociremote.WithRemoteOptions(o.rOpt...))
	}

	checkOpts.RegistryClientOpts = co

	// If a public key is provided, it will use it to verify the signature.
	// If there is no public key provided, it will try keyless verification.
	// https://github.com/sigstore/cosign/blob/main/KEYLESS.md.
	if len(o.publicKey) > 0 {
		checkOpts.Offline = true
		// TODO(hidde): this is an oversight in our implementation. As it is
		//  theoretically possible to have a custom PK, without disabling tlog.
		checkOpts.IgnoreTlog = true

		pubKeyRaw, err := cryptoutils.UnmarshalPEMToPublicKey(o.publicKey)
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

		// Initialize TrustedMaterial for v3/Bundle verification
		f.mu.Lock()
		if f.trustedMaterial != nil {
			checkOpts.TrustedMaterial = f.trustedMaterial
			f.mu.Unlock()
		} else {
			// Check if we should init or retry
			if f.initErr == nil || time.Since(f.lastAttempt) >= f.retryInterval {
				f.lastAttempt = time.Now()
				// TODO(stealthybox): it would be nice to control the http client here for the TrustedRoot fetcher
				//  with the current state of this part of the cosign SDK, that would involve duplicating a lot of
				//  their ENV, options, and defaulting code.
				f.trustedMaterial, f.initErr = cosign.TrustedRoot()
			}

			err := f.initErr
			tm := f.trustedMaterial
			f.mu.Unlock()

			if err != nil {
				return nil, fmt.Errorf("unable to initialize trusted root: %w", err)
			}
			checkOpts.TrustedMaterial = tm
		}

		// Initialize legacy setup for v2 compatibility

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

// Verify verifies the authenticity of the given ref OCI image.
// Both cosign v2 signatures and cosign v3 bundles are supported by
// attempting to discover bundles before verification.
// Bundles can be located either via the OCI 1.1 referrer API or an
// OCI 1.0 referrer tag.
// It returns a boolean indicating if the verification was successful.
// It returns an error if the verification fails, nil otherwise.
func (v *CosignVerifier) Verify(ctx context.Context, ref name.Reference) (soci.VerificationResult, error) {
	var signatures []oci.Signature
	// copy options since we'll need to change them based on bundle discovery on the ref
	opts := *v.opts
	newBundles, _, err := cosign.GetBundles(ctx, ref, opts.RegistryClientOpts)
	// if no bundles are returned, let's fallback to the cosign v2 behavior, similar to the cosign CLI
	if len(newBundles) == 0 || err != nil {
		opts.NewBundleFormat = false
		signatures, _, err = cosign.VerifyImageSignatures(ctx, ref, &opts)
	} else {
		opts.NewBundleFormat = true
		signatures, _, err = cosign.VerifyImageAttestations(ctx, ref, &opts)
	}
	if err != nil {
		return soci.VerificationResultFailed, err
	}

	if len(signatures) == 0 {
		return soci.VerificationResultFailed, nil
	}

	return soci.VerificationResultSuccess, nil
}
