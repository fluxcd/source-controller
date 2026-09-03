/*
Copyright 2026 The Flux authors

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
	"fmt"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// trustedRootHeader is the header for a trusted root JSON document.
const trustedRootHeader = `"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1"`

// rekorEntryJSON is a minimal but complete transparency log entry. The public
// key is the same test ECDSA P-256 key used elsewhere in this package.
const rekorEntryJSON = `{
	"baseUrl": "https://rekor.example.com",
	"hashAlgorithm": "SHA2_256",
	"publicKey": {
		"rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
		"keyDetails": "PKIX_ECDSA_P256_SHA_256",
		"validFor": {"start": "2021-01-12T11:53:27.000Z"}
	},
	"logId": {"keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="}
}`

// fulcioEntryJSON is a minimal Fulcio CA entry. The certificate is the
// sigstore.dev test CA used in the public TUF repository.
const fulcioEntryJSON = `{
	"subject": {"organization": "test", "commonName": "test"},
	"uri": "https://fulcio.example.com",
	"certChain": {"certificates": [{"rawBytes": "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ=="}]},
	"validFor": {"start": "2021-03-07T03:20:29.000Z", "end": "2099-12-31T23:59:59.999Z"}
}`

// ctlogEntryJSON is a minimal CT log entry sharing the same test public key.
const ctlogEntryJSON = `{
	"baseUrl": "https://ctfe.example.com",
	"hashAlgorithm": "SHA2_256",
	"publicKey": {
		"rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
		"keyDetails": "PKIX_ECDSA_P256_SHA_256",
		"validFor": {"start": "2021-01-12T11:53:27.000Z"}
	},
	"logId": {"keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="}
}`

// tsaEntryJSON is a minimal timestamping authority entry. The certificate is
// reused for both the leaf and the chain root since the trusted root format
// only requires a non-empty cert chain to populate TimestampingAuthorities().
const tsaEntryJSON = `{
	"subject": {"organization": "test", "commonName": "test-tsa"},
	"uri": "https://tsa.example.com",
	"certChain": {"certificates": [{"rawBytes": "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ=="}]},
	"validFor": {"start": "2021-03-07T03:20:29.000Z"}
}`

// makeTrustedRoot composes a trusted root JSON document with the requested
// component sets.
func makeTrustedRoot(t *testing.T, withFulcio, withRekor, withCTLog, withTSA bool) *root.TrustedRoot {
	t.Helper()
	parts := []string{trustedRootHeader}
	if withFulcio {
		parts = append(parts, fmt.Sprintf(`"certificateAuthorities": [%s]`, fulcioEntryJSON))
	}
	if withRekor {
		parts = append(parts, fmt.Sprintf(`"tlogs": [%s]`, rekorEntryJSON))
	}
	if withCTLog {
		parts = append(parts, fmt.Sprintf(`"ctlogs": [%s]`, ctlogEntryJSON))
	}
	if withTSA {
		parts = append(parts, fmt.Sprintf(`"timestampAuthorities": [%s]`, tsaEntryJSON))
	}
	jsonStr := "{" + strings.Join(parts, ",") + "}"
	tr, err := root.NewTrustedRootFromJSON([]byte(jsonStr))
	if err != nil {
		t.Fatalf("failed to parse composed trusted root: %v\nJSON: %s", err, jsonStr)
	}
	return tr
}

func TestDetectTrustedRootCapabilities(t *testing.T) {
	tests := []struct {
		name    string
		fulcio  bool
		rekor   bool
		ctlog   bool
		tsa     bool
		wantCap trustedRootCapabilities
	}{
		{
			name:   "all components",
			fulcio: true, rekor: true, ctlog: true, tsa: true,
			wantCap: trustedRootCapabilities{HasFulcio: true, HasRekor: true, HasCTLog: true, HasTSA: true},
		},
		{
			name:    "rekor only",
			rekor:   true,
			wantCap: trustedRootCapabilities{HasRekor: true},
		},
		{
			name:    "fulcio only",
			fulcio:  true,
			wantCap: trustedRootCapabilities{HasFulcio: true},
		},
		{
			name:    "tsa only",
			tsa:     true,
			wantCap: trustedRootCapabilities{HasTSA: true},
		},
		{
			name:   "fulcio and rekor (typical keyless)",
			fulcio: true, rekor: true,
			wantCap: trustedRootCapabilities{HasFulcio: true, HasRekor: true},
		},
		{
			name:   "fulcio and ctlog without rekor",
			fulcio: true, ctlog: true,
			wantCap: trustedRootCapabilities{HasFulcio: true, HasCTLog: true},
		},
		{
			name:  "rekor and tsa",
			rekor: true, tsa: true,
			wantCap: trustedRootCapabilities{HasRekor: true, HasTSA: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			tr := makeTrustedRoot(t, tt.fulcio, tt.rekor, tt.ctlog, tt.tsa)
			got := detectTrustedRootCapabilities(tr)
			g.Expect(got).To(Equal(tt.wantCap))
		})
	}
}

func TestApplyTrustedRootAutoDetection_Keyless(t *testing.T) {
	tests := []struct {
		name                    string
		fulcio                  bool
		rekor                   bool
		ctlog                   bool
		tsa                     bool
		wantIgnoreTlog          bool
		wantUseSignedTimestamps bool
		wantIgnoreSCT           bool
	}{
		{
			name:   "fulcio + rekor + ctlog (typical public Sigstore)",
			fulcio: true, rekor: true, ctlog: true,
			wantIgnoreTlog:          false,
			wantUseSignedTimestamps: false,
			wantIgnoreSCT:           false,
		},
		{
			name:   "fulcio + tsa (no tlog)",
			fulcio: true, tsa: true,
			wantIgnoreTlog:          true,
			wantUseSignedTimestamps: true,
			wantIgnoreSCT:           true,
		},
		{
			name:                    "rekor only (tlog-only policy)",
			rekor:                   true,
			wantIgnoreTlog:          false,
			wantUseSignedTimestamps: false,
			wantIgnoreSCT:           true,
		},
		{
			name:   "all four components",
			fulcio: true, rekor: true, ctlog: true, tsa: true,
			wantIgnoreTlog:          false,
			wantUseSignedTimestamps: true,
			wantIgnoreSCT:           false,
		},
		{
			// GitHub-style immutable releases: keyless verification anchored
			// in TSA timestamps and Fulcio identity rather than a Rekor tlog.
			name:   "fulcio + ctlog + tsa (GitHub-style, no Rekor)",
			fulcio: true, ctlog: true, tsa: true,
			wantIgnoreTlog:          true,
			wantUseSignedTimestamps: true,
			wantIgnoreSCT:           false,
		},
		{
			name:                    "tsa only",
			tsa:                     true,
			wantIgnoreTlog:          true,
			wantUseSignedTimestamps: true,
			wantIgnoreSCT:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			tr := makeTrustedRoot(t, tt.fulcio, tt.rekor, tt.ctlog, tt.tsa)
			caps := detectTrustedRootCapabilities(tr)
			co := &cosign.CheckOpts{}
			applyTrustedRootAutoDetection(co, tr, caps)
			g.Expect(co.TrustedMaterial).NotTo(BeNil())
			g.Expect(co.IgnoreTlog).To(Equal(tt.wantIgnoreTlog))
			g.Expect(co.UseSignedTimestamps).To(Equal(tt.wantUseSignedTimestamps))
			g.Expect(co.IgnoreSCT).To(Equal(tt.wantIgnoreSCT))
			g.Expect(co.RekorClient).To(BeNil())
		})
	}
}

func TestNewCosignVerifier_KeylessAutoDetect(t *testing.T) {
	ctx := context.Background()
	vf := NewCosignVerifierFactory()

	t.Run("rejects empty bundle", func(t *testing.T) {
		g := NewWithT(t)
		tr := makeTrustedRoot(t, false, false, false, false)
		marshaled, err := tr.MarshalJSON()
		g.Expect(err).NotTo(HaveOccurred())
		_, err = vf.NewCosignVerifier(ctx, WithTrustedRoot(marshaled))
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("must contain Fulcio and at least one of Rekor or TSA"))
	})

	for _, tt := range []struct {
		name   string
		fulcio bool
		rekor  bool
		ctlog  bool
		tsa    bool
	}{
		{name: "rejects fulcio only", fulcio: true},
		{name: "rejects rekor only", rekor: true},
		{name: "rejects tsa only", tsa: true},
		{name: "rejects rekor + tsa without fulcio", rekor: true, tsa: true},
		{name: "rejects fulcio + ctlog without time source", fulcio: true, ctlog: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			tr := makeTrustedRoot(t, tt.fulcio, tt.rekor, tt.ctlog, tt.tsa)
			marshaled, err := tr.MarshalJSON()
			g.Expect(err).NotTo(HaveOccurred())
			_, err = vf.NewCosignVerifier(ctx, WithTrustedRoot(marshaled))
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring("must contain Fulcio and at least one of Rekor or TSA"))
		})
	}

	t.Run("fulcio + rekor matches typical keyless", func(t *testing.T) {
		g := NewWithT(t)
		tr := makeTrustedRoot(t, true, true, false, false)
		marshaled, err := tr.MarshalJSON()
		g.Expect(err).NotTo(HaveOccurred())
		v, err := vf.NewCosignVerifier(ctx, WithTrustedRoot(marshaled))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(v.opts.TrustedMaterial).NotTo(BeNil())
		g.Expect(v.opts.RekorClient).To(BeNil())
		g.Expect(v.rekorURLs).To(Equal([]string{"https://rekor.example.com"}))
		g.Expect(v.opts.IgnoreTlog).To(BeFalse())
		g.Expect(v.opts.UseSignedTimestamps).To(BeFalse())
		g.Expect(v.opts.IgnoreSCT).To(BeTrue())
	})

	t.Run("fulcio + tsa skips tlog and requires signed timestamps", func(t *testing.T) {
		g := NewWithT(t)
		tr := makeTrustedRoot(t, true, false, false, true)
		marshaled, err := tr.MarshalJSON()
		g.Expect(err).NotTo(HaveOccurred())
		v, err := vf.NewCosignVerifier(ctx, WithTrustedRoot(marshaled))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(v.opts.TrustedMaterial).NotTo(BeNil())
		g.Expect(v.opts.RekorClient).To(BeNil())
		g.Expect(v.rekorURLs).To(BeEmpty())
		g.Expect(v.opts.IgnoreTlog).To(BeTrue())
		g.Expect(v.opts.UseSignedTimestamps).To(BeTrue())
	})
}

func TestNewCosignVerifier_KeyedAutoDetect(t *testing.T) {
	ctx := context.Background()
	vf := NewCosignVerifierFactory()

	// A throwaway ECDSA P-256 public key in PEM form, generated for tests.
	pubKey := []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----
`)

	t.Run("public key without trusted root keeps legacy offline tlog skip", func(t *testing.T) {
		g := NewWithT(t)
		v, err := vf.NewCosignVerifier(ctx, WithPublicKey(pubKey))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(v.opts.SigVerifier).NotTo(BeNil())
		g.Expect(v.opts.TrustedMaterial).To(BeNil())
		g.Expect(v.opts.IgnoreTlog).To(BeTrue())
		g.Expect(v.opts.Offline).To(BeTrue())
		g.Expect(v.opts.UseSignedTimestamps).To(BeFalse())
	})

	t.Run("public key + rekor-only trusted root enables tlog verification", func(t *testing.T) {
		g := NewWithT(t)
		tr := makeTrustedRoot(t, false, true, false, false)
		marshaled, err := tr.MarshalJSON()
		g.Expect(err).NotTo(HaveOccurred())
		v, err := vf.NewCosignVerifier(ctx,
			WithPublicKey(pubKey),
			WithTrustedRoot(marshaled),
		)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(v.opts.SigVerifier).NotTo(BeNil())
		g.Expect(v.opts.TrustedMaterial).NotTo(BeNil())
		g.Expect(v.opts.RekorClient).To(BeNil())
		g.Expect(v.rekorURLs).To(Equal([]string{"https://rekor.example.com"}))
		g.Expect(v.opts.IgnoreTlog).To(BeFalse())
		g.Expect(v.opts.UseSignedTimestamps).To(BeFalse())
	})

	t.Run("public key + tsa-only trusted root enables signed timestamps and skips tlog", func(t *testing.T) {
		g := NewWithT(t)
		tr := makeTrustedRoot(t, false, false, false, true)
		marshaled, err := tr.MarshalJSON()
		g.Expect(err).NotTo(HaveOccurred())
		v, err := vf.NewCosignVerifier(ctx,
			WithPublicKey(pubKey),
			WithTrustedRoot(marshaled),
		)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(v.opts.SigVerifier).NotTo(BeNil())
		g.Expect(v.opts.TrustedMaterial).NotTo(BeNil())
		g.Expect(v.opts.RekorClient).To(BeNil())
		g.Expect(v.rekorURLs).To(BeEmpty())
		g.Expect(v.opts.IgnoreTlog).To(BeTrue())
		g.Expect(v.opts.UseSignedTimestamps).To(BeTrue())
	})

	t.Run("public key + rekor + tsa requires both", func(t *testing.T) {
		g := NewWithT(t)
		tr := makeTrustedRoot(t, false, true, false, true)
		marshaled, err := tr.MarshalJSON()
		g.Expect(err).NotTo(HaveOccurred())
		v, err := vf.NewCosignVerifier(ctx,
			WithPublicKey(pubKey),
			WithTrustedRoot(marshaled),
		)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(v.opts.RekorClient).To(BeNil())
		g.Expect(v.rekorURLs).To(Equal([]string{"https://rekor.example.com"}))
		g.Expect(v.opts.IgnoreTlog).To(BeFalse())
		g.Expect(v.opts.UseSignedTimestamps).To(BeTrue())
	})

	t.Run("public key + ctlog-only trusted root is allowed for keyed verification", func(t *testing.T) {
		g := NewWithT(t)
		tr := makeTrustedRoot(t, false, false, true, false)
		marshaled, err := tr.MarshalJSON()
		g.Expect(err).NotTo(HaveOccurred())
		v, err := vf.NewCosignVerifier(ctx,
			WithPublicKey(pubKey),
			WithTrustedRoot(marshaled),
		)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(v.opts.SigVerifier).NotTo(BeNil())
		g.Expect(v.opts.TrustedMaterial).NotTo(BeNil())
		g.Expect(v.opts.IgnoreTlog).To(BeTrue())
		g.Expect(v.opts.IgnoreSCT).To(BeTrue())
	})
}
