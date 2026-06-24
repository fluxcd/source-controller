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
	"net"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/gomega"
	coptions "github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/pkg/cosign"

	soci "github.com/fluxcd/source-controller/internal/oci"
	testregistry "github.com/fluxcd/source-controller/tests/registry"
)

// TestVerifyInsecureV3Bundle tests v3 bundle-format signature verification
// against an HTTP-only registry accessed via a non-loopback hostname.
//
// go-containerregistry uses HTTP implicitly for localhost/127.0.0.1/RFC1918.
// This test uses a fake external hostname to cover the case of in-cluster
// registries like "my-registry:5000" where name.Insecure must be explicit.
//
// GetBundles() creates new name.Reference objects for bundle digests via
// name.ParseReference without carrying over name.Insecure from the original
// ref, so WithInsecure(true) on the verifier is needed to make it work.
func TestVerifyInsecureV3Bundle(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	// Start an HTTP-only registry on a random port
	registryAddr := testregistry.New(t)
	_, port, _ := net.SplitHostPort(registryAddr)

	// Use a fake external hostname that requires name.Insecure
	fakeHost := "fake-external-registry.example.com"
	fakeAddr := fmt.Sprintf("%s:%s", fakeHost, port)

	// Custom transport that resolves the fake hostname to 127.0.0.1
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if host, p, _ := net.SplitHostPort(addr); host == fakeHost {
				addr = net.JoinHostPort("127.0.0.1", p)
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}

	// Generate cosign key pair
	keys, err := cosign.GenerateKeyPair(func(b bool) ([]byte, error) {
		return []byte(""), nil
	})
	g.Expect(err).NotTo(HaveOccurred())

	tmpDir := t.TempDir()
	keyPath := path.Join(tmpDir, "cosign.key")
	err = os.WriteFile(keyPath, keys.PrivateBytes, 0600)
	g.Expect(err).NotTo(HaveOccurred())

	// Push a test image using the real loopback address
	realRef := fmt.Sprintf("%s/test/v3bundle:v1", registryAddr)
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	err = crane.Push(img, realRef)
	g.Expect(err).NotTo(HaveOccurred())

	// Sign with v3 bundle format using the real loopback address
	// (the bundle is stored by digest, so it's discoverable from any hostname)
	pf := func(_ bool) ([]byte, error) { return []byte(""), nil }
	ko := coptions.KeyOpts{
		KeyRef:          keyPath,
		PassFunc:        pf,
		NewBundleFormat: true,
	}
	ro := &coptions.RootOptions{Timeout: 30 * time.Second}
	err = sign.SignCmd(ctx, ro, ko, coptions.SignOptions{
		Upload:           true,
		SkipConfirmation: true,
		TlogUpload:       false,
		NewBundleFormat:  true,
		Registry:         coptions.RegistryOptions{AllowInsecure: true, AllowHTTPRegistry: true},
	}, []string{realRef})
	g.Expect(err).NotTo(HaveOccurred())

	// Parse reference with name.Insecure (as source-controller does for spec.insecure=true)
	ref, err := name.ParseReference(fmt.Sprintf("%s/test/v3bundle:v1", fakeAddr), name.Insecure)
	g.Expect(err).NotTo(HaveOccurred())

	// Verify using the CosignVerifier with the custom transport
	vf := NewCosignVerifierFactory()
	verifier, err := vf.NewCosignVerifier(ctx,
		WithPublicKey(keys.PublicBytes),
		WithRemoteOptions(remote.WithTransport(transport)),
		WithInsecure(true),
	)
	g.Expect(err).NotTo(HaveOccurred())

	result, err := verifier.Verify(ctx, ref)
	g.Expect(err).NotTo(HaveOccurred(), "v3 bundle verification should succeed on insecure registry with non-loopback hostname")
	g.Expect(result).To(Equal(soci.VerificationResultSuccess))
}
