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
	"crypto/tls"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio"
	coptions "github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	rekorgenclient "github.com/sigstore/rekor/pkg/generated/client"

	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	soci "github.com/fluxcd/source-controller/internal/oci"
)

// options is a struct that holds options for verifier.
type options struct {
	publicKey   []byte
	rOpt        []remote.Option
	identities  []cosign.Identity
	trustedRoot []byte
	insecure    bool
	tlsConfig   *tls.Config
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

// WithTrustedRoot sets the Sigstore trusted root JSON bytes. When provided,
// verification uses the custom trusted root instead of the public Sigstore
// TUF root. Rekor, Fulcio, CT log, and TSA enforcement are auto-detected
// from the trusted root contents:
//   - If the trusted root contains transparency log entries, Rekor inclusion
//     verification is required. Bundled verification uses the log IDs and
//     keys in the trusted root; legacy online lookup tries all Rekor URLs
//     declared in the trusted root. Otherwise tlog verification is skipped.
//   - If the trusted root contains timestamping authorities, RFC3161 signed
//     timestamps are required. Otherwise they are not enforced.
//   - If the trusted root contains certificate transparency logs, an embedded
//     SCT is required for keyless verification. Otherwise SCT verification
//     is skipped. SCT enforcement is moot for keyed signatures.
//   - If the trusted root contains Fulcio certificate authorities, it is
//     used to validate the keyless signing certificate chain. It is moot
//     for keyed signatures.
//
// For keyless verification, Fulcio and at least one durable time source
// (Rekor or TSA) must be present.
func WithTrustedRoot(trustedRoot []byte) Options {
	return func(opts *options) {
		opts.trustedRoot = trustedRoot
	}
}

// WithInsecure sets the verifier to use HTTP when discovering v3 bundle
// signatures from the container registry via OCI referrers tag fallback.
// Does not affect Rekor connections.
func WithInsecure(insecure bool) Options {
	return func(opts *options) {
		opts.insecure = insecure
	}
}

// WithTLSConfig sets the TLS configuration for Rekor client connections.
// When nil, the system trust store is used.
func WithTLSConfig(tlsConfig *tls.Config) Options {
	return func(opts *options) {
		opts.tlsConfig = tlsConfig
	}
}

// CosignVerifier is a struct which is responsible for executing verification logic.
type CosignVerifier struct {
	opts      *cosign.CheckOpts
	insecure  bool
	rekorURLs []string
	tlsConfig *tls.Config
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

	// Parse the optional custom trusted root once so it can drive
	// auto-detection in both the keyed and keyless paths.
	var (
		customRoot *root.TrustedRoot
		caps       trustedRootCapabilities
	)
	if len(o.trustedRoot) > 0 {
		customRoot, err = root.NewTrustedRootFromJSON(o.trustedRoot)
		if err != nil {
			return nil, fmt.Errorf("unable to parse trusted root: %w", err)
		}
		caps = detectTrustedRootCapabilities(customRoot)
	}

	// If a public key is provided, use it to verify the signature.
	// https://github.com/sigstore/cosign/blob/main/KEYLESS.md.
	if len(o.publicKey) > 0 {
		pubKeyRaw, err := cryptoutils.UnmarshalPEMToPublicKey(o.publicKey)
		if err != nil {
			return nil, err
		}

		checkOpts.SigVerifier, err = signature.LoadVerifier(pubKeyRaw, crypto.SHA256)
		if err != nil {
			return nil, err
		}

		// Without a custom trusted root, retain the legacy behavior of
		// disabling tlog verification entirely.
		if customRoot == nil {
			checkOpts.Offline = true
			checkOpts.IgnoreTlog = true
			return &CosignVerifier{opts: checkOpts, insecure: o.insecure, tlsConfig: o.tlsConfig}, nil
		}

		// With a custom trusted root, opt into verifying any tlog or TSA
		// material the user provided alongside the public key. CT logs and
		// Fulcio CAs in the bundle are not meaningful for keyed signatures.
		applyTrustedRootAutoDetection(checkOpts, customRoot, caps)
		return &CosignVerifier{
			opts:      checkOpts,
			insecure:  o.insecure,
			rekorURLs: rekorURLsFromTrustedRoot(customRoot),
			tlsConfig: o.tlsConfig,
		}, nil
	}

	// Keyless verification: when a custom trusted root is provided, use it
	// directly instead of the public Sigstore infrastructure. Rekor, Fulcio,
	// CT log, and TSA enforcement are auto-detected from the bundle contents.
	if customRoot != nil {
		if !caps.HasFulcio || (!caps.HasRekor && !caps.HasTSA) {
			return nil, fmt.Errorf("custom trusted root for keyless verification must contain Fulcio and at least one of Rekor or TSA material")
		}
		applyTrustedRootAutoDetection(checkOpts, customRoot, caps)
		return &CosignVerifier{
			opts:      checkOpts,
			insecure:  o.insecure,
			rekorURLs: rekorURLsFromTrustedRoot(customRoot),
			tlsConfig: o.tlsConfig,
		}, nil
	}

	// Keyless verification using the public Sigstore infrastructure.
	checkOpts.RekorClient, err = newRekorClient(coptions.DefaultRekorURL, o.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create Rekor client: %w", err)
	}

	// Initialize TrustedMaterial for v3/Bundle verification.
	f.mu.Lock()
	if f.trustedMaterial != nil {
		checkOpts.TrustedMaterial = f.trustedMaterial
		f.mu.Unlock()
	} else {
		// Check if we should init or retry.
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

	// Initialize legacy setup for v2 compatibility.

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

	return &CosignVerifier{opts: checkOpts, insecure: o.insecure, tlsConfig: o.tlsConfig}, nil
}

// newRekorClient creates a Rekor client with optional TLS configuration.
// If tlsConfig is nil, the default system trust store is used.
func newRekorClient(rekorURL string, tlsConfig *tls.Config) (*rekorgenclient.Rekor, error) {
	opts := []rekorclient.Option{rekorclient.WithUserAgent(coptions.UserAgent())}
	if tlsConfig != nil {
		opts = append(opts, rekorclient.WithTLSConfig(tlsConfig))
	}
	return rekorclient.GetRekorClient(rekorURL, opts...)
}

// rekorURLsFromTrustedRoot extracts all Rekor base URLs from a trusted root's
// transparency log entries in deterministic order. Empty URLs are omitted so
// bundled verification can still use the log key material without enabling
// legacy online lookup.
func rekorURLsFromTrustedRoot(tr *root.TrustedRoot) []string {
	logs := tr.RekorLogs()
	logIDs := make([]string, 0, len(logs))
	for logID := range logs {
		logIDs = append(logIDs, logID)
	}
	sort.Strings(logIDs)

	urls := make([]string, 0, len(logIDs))
	seen := make(map[string]struct{}, len(logIDs))
	for _, logID := range logIDs {
		baseURL := logs[logID].BaseURL
		if baseURL == "" {
			continue
		}
		if _, ok := seen[baseURL]; ok {
			continue
		}
		seen[baseURL] = struct{}{}
		urls = append(urls, baseURL)
	}

	return urls
}

// trustedRootCapabilities summarizes which Sigstore components are present in
// a custom trusted root. It is used to derive cosign CheckOpts policy flags
// when a custom trusted root is provided so that the user does not have to
// configure Rekor/Fulcio/TSA enforcement separately from the bundle contents.
type trustedRootCapabilities struct {
	// HasFulcio is true when the trusted root contains at least one Fulcio
	// certificate authority. It is required for keyless certificate chain
	// verification.
	HasFulcio bool
	// HasRekor is true when the trusted root contains at least one
	// transparency log entry. When true the verifier requires a Rekor
	// inclusion proof; when false tlog verification is skipped.
	HasRekor bool
	// HasTSA is true when the trusted root contains at least one timestamping
	// authority. When true the verifier requires an RFC3161 signed timestamp.
	HasTSA bool
	// HasCTLog is true when the trusted root contains at least one
	// certificate transparency log. When true keyless verification requires
	// an embedded SCT in the signing certificate. It has no effect on keyed
	// signatures.
	HasCTLog bool
}

// detectTrustedRootCapabilities inspects a trusted root and returns which
// Sigstore components are present. The returned struct drives auto-detection
// of cosign verification policy flags.
func detectTrustedRootCapabilities(tr *root.TrustedRoot) trustedRootCapabilities {
	return trustedRootCapabilities{
		HasFulcio: len(tr.FulcioCertificateAuthorities()) > 0,
		HasRekor:  len(tr.RekorLogs()) > 0,
		HasTSA:    len(tr.TimestampingAuthorities()) > 0,
		HasCTLog:  len(tr.CTLogs()) > 0,
	}
}

// applyTrustedRootAutoDetection configures the cosign CheckOpts to require or
// ignore each Sigstore component (Rekor, TSA, CT log) based on the contents
// of the custom trusted root.
//
// The trustedRootCapabilities must already have been computed from tr; it is
// passed in to avoid recomputation.
//
// Notes on combinations:
//   - Keyed (SigVerifier set) ignores HasFulcio and HasCTLog: a public key
//     does not need a certificate chain or an SCT.
func applyTrustedRootAutoDetection(checkOpts *cosign.CheckOpts, tr *root.TrustedRoot, caps trustedRootCapabilities) {
	checkOpts.TrustedMaterial = tr

	// Rekor: require a transparency log inclusion proof if and only if the
	// trusted root contains at least one Rekor public key. Bundled
	// verification matches log entries by ID against TrustedMaterial; legacy
	// online lookup is handled during Verify by trying all declared BaseURLs.
	checkOpts.IgnoreTlog = !caps.HasRekor

	// TSA: require an RFC3161 signed timestamp if and only if the trusted
	// root contains at least one timestamping authority.
	checkOpts.UseSignedTimestamps = caps.HasTSA

	// SCT: require an embedded signed certificate timestamp if and only if
	// the trusted root contains at least one CT log. Has no effect when a
	// public key is set, because SCT verification is gated on a certificate.
	checkOpts.IgnoreSCT = checkOpts.SigVerifier != nil || !caps.HasCTLog
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

	// Pass insecure to GetBundles for internal bundle digest references.
	var nameOpts []name.Option
	if v.insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}

	newBundles, _, err := cosign.GetBundles(ctx, ref, opts.RegistryClientOpts, nameOpts...)
	// if no bundles are returned, let's fallback to the cosign v2 behavior, similar to the cosign CLI
	if len(newBundles) == 0 || err != nil {
		opts.NewBundleFormat = false
		signatures, err = v.verifyImageSignatures(ctx, ref, opts)
	} else {
		opts.NewBundleFormat = true
		signatures, err = v.verifyImageAttestations(ctx, ref, opts, nameOpts...)
	}
	if err != nil {
		return soci.VerificationResultFailed, err
	}

	if len(signatures) == 0 {
		return soci.VerificationResultFailed, nil
	}

	return soci.VerificationResultSuccess, nil
}

// verifyImageSignatures verifies legacy signatures, retrying online Rekor
// lookup against each Rekor URL from a custom trusted root when needed.
func (v *CosignVerifier) verifyImageSignatures(ctx context.Context, ref name.Reference, opts cosign.CheckOpts) ([]oci.Signature, error) {
	return v.verifyWithRekorURLs(opts, func(opts cosign.CheckOpts) ([]oci.Signature, error) {
		signatures, _, err := cosign.VerifyImageSignatures(ctx, ref, &opts)
		return signatures, err
	})
}

// verifyImageAttestations verifies attestations, retrying legacy online Rekor
// lookup against each Rekor URL from a custom trusted root when needed.
func (v *CosignVerifier) verifyImageAttestations(ctx context.Context, ref name.Reference, opts cosign.CheckOpts, nameOpts ...name.Option) ([]oci.Signature, error) {
	return v.verifyWithRekorURLs(opts, func(opts cosign.CheckOpts) ([]oci.Signature, error) {
		attestations, _, err := cosign.VerifyImageAttestations(ctx, ref, &opts, nameOpts...)
		return attestations, err
	})
}

type verifyFunc func(opts cosign.CheckOpts) ([]oci.Signature, error)

func (v *CosignVerifier) verifyWithRekorURLs(opts cosign.CheckOpts, verify verifyFunc) ([]oci.Signature, error) {
	signatures, err := verify(opts)
	if err == nil || opts.NewBundleFormat || opts.IgnoreTlog || len(v.rekorURLs) == 0 {
		return signatures, err
	}

	errs := []error{err}
	for _, rekorURL := range v.rekorURLs {
		rekorClient, clientErr := newRekorClient(rekorURL, v.tlsConfig)
		if clientErr != nil {
			errs = append(errs, fmt.Errorf("unable to create Rekor client for %q: %w", rekorURL, clientErr))
			continue
		}

		retryOpts := opts
		retryOpts.RekorClient = rekorClient
		signatures, err = verify(retryOpts)
		if err == nil {
			return signatures, nil
		}
		errs = append(errs, fmt.Errorf("rekor %q: %w", rekorURL, err))
	}

	return nil, errors.Join(errs...)
}
