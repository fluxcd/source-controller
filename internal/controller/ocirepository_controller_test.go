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

package controller

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	. "github.com/onsi/gomega"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	coptions "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	oras "oras.land/oras-go/v2/registry/remote"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	kstatus "github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/fluxcd/pkg/apis/meta"
	intdigest "github.com/fluxcd/pkg/artifact/digest"
	"github.com/fluxcd/pkg/artifact/storage"
	"github.com/fluxcd/pkg/auth"
	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/oci"
	"github.com/fluxcd/pkg/runtime/conditions"
	conditionscheck "github.com/fluxcd/pkg/runtime/conditions/check"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/tar"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
	serror "github.com/werf/nelm-source-controller/internal/error"
	snotation "github.com/werf/nelm-source-controller/internal/oci/notation"
	sreconcile "github.com/werf/nelm-source-controller/internal/reconcile"
	testproxy "github.com/werf/nelm-source-controller/tests/proxy"
)

func TestOCIRepositoryReconciler_deleteBeforeFinalizer(t *testing.T) {
	g := NewWithT(t)

	namespaceName := "ocirepo-" + randStringRunes(5)
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
	}
	g.Expect(k8sClient.Create(ctx, namespace)).ToNot(HaveOccurred())
	t.Cleanup(func() {
		g.Expect(k8sClient.Delete(ctx, namespace)).NotTo(HaveOccurred())
	})

	ocirepo := &sourcev1.OCIRepository{}
	ocirepo.Name = "test-ocirepo"
	ocirepo.Namespace = namespaceName
	ocirepo.Spec = sourcev1.OCIRepositorySpec{
		Interval: metav1.Duration{Duration: interval},
		URL:      "oci://example.com",
	}
	// Add a test finalizer to prevent the object from getting deleted.
	ocirepo.SetFinalizers([]string{"test-finalizer"})
	g.Expect(k8sClient.Create(ctx, ocirepo)).NotTo(HaveOccurred())
	// Add deletion timestamp by deleting the object.
	g.Expect(k8sClient.Delete(ctx, ocirepo)).NotTo(HaveOccurred())

	r := &OCIRepositoryReconciler{
		Client:        k8sClient,
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
	}
	// NOTE: Only a real API server responds with an error in this scenario.
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ocirepo)})
	g.Expect(err).NotTo(HaveOccurred())
}

func TestOCIRepository_Reconcile(t *testing.T) {
	g := NewWithT(t)

	// Registry server with public images
	tmpDir := t.TempDir()
	regServer, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	if err != nil {
		g.Expect(err).ToNot(HaveOccurred())
	}
	t.Cleanup(func() {
		regServer.Close()
	})

	podinfoVersions, err := pushMultiplePodinfoImages(regServer.registryHost, true, "6.1.4", "6.1.5", "6.1.6")
	g.Expect(err).ToNot(HaveOccurred())

	tests := []struct {
		name           string
		url            string
		tag            string
		semver         string
		revision       string
		mediaType      string
		operation      string
		assertArtifact []artifactFixture
	}{
		{
			name:      "public tag",
			url:       podinfoVersions["6.1.6"].url,
			tag:       podinfoVersions["6.1.6"].tag,
			revision:  fmt.Sprintf("%s@%s", podinfoVersions["6.1.6"].tag, podinfoVersions["6.1.6"].digest.String()),
			mediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
			operation: sourcev1.OCILayerCopy,
			assertArtifact: []artifactFixture{
				{
					expectedPath:     "kustomize/deployment.yaml",
					expectedChecksum: "6fd625effe6bb805b6a78943ee082a4412e763edb7fcaed6e8fe644d06cbf423",
				},
				{
					expectedPath:     "kustomize/hpa.yaml",
					expectedChecksum: "d20e92e3b2926ebfee1644be0f4d0abadebfa95a8005c12f71bfd534a4be4ff9",
				},
			},
		},
		{
			name:     "public semver",
			url:      podinfoVersions["6.1.5"].url,
			semver:   ">= 6.1 <= 6.1.5",
			revision: fmt.Sprintf("%s@%s", podinfoVersions["6.1.5"].tag, podinfoVersions["6.1.5"].digest.String()),
			assertArtifact: []artifactFixture{
				{
					expectedPath:     "kustomize/deployment.yaml",
					expectedChecksum: "dce4f5f780a8e8994b06031e5b567bf488ceaaaabd9bd3fc278b4f3bfc8c577b",
				},
				{
					expectedPath:     "kustomize/hpa.yaml",
					expectedChecksum: "d20e92e3b2926ebfee1644be0f4d0abadebfa95a8005c12f71bfd534a4be4ff9",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ns, err := testEnv.CreateNamespace(ctx, "ocirepository-reconcile-test")
			g.Expect(err).ToNot(HaveOccurred())
			defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

			origObj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "ocirepository-reconcile",
					Namespace:    ns.Name,
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL:       tt.url,
					Interval:  metav1.Duration{Duration: 60 * time.Minute},
					Reference: &sourcev1.OCIRepositoryRef{},
					Insecure:  true,
				},
			}
			obj := origObj.DeepCopy()

			if tt.tag != "" {
				obj.Spec.Reference.Tag = tt.tag
			}
			if tt.semver != "" {
				obj.Spec.Reference.SemVer = tt.semver
			}
			if tt.mediaType != "" {
				obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{MediaType: tt.mediaType}

				if tt.operation != "" {
					obj.Spec.LayerSelector.Operation = tt.operation
				}
			}

			g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

			key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

			// Wait for the finalizer to be set
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, obj); err != nil {
					return false
				}
				return len(obj.Finalizers) > 0
			}, timeout).Should(BeTrue())

			// Wait for the object to be Ready
			waitForSourceReadyWithArtifact(ctx, g, obj)

			// Check if the revision matches the expected revision
			g.Expect(obj.Status.Artifact.Revision).To(Equal(tt.revision))

			// Check if the metadata matches the expected annotations
			g.Expect(obj.Status.Artifact.Metadata[oci.SourceAnnotation]).To(ContainSubstring("podinfo"))
			g.Expect(obj.Status.Artifact.Metadata[oci.RevisionAnnotation]).To(ContainSubstring(tt.tag))

			// Check if the artifact storage path matches the expected file path
			localPath := testStorage.LocalPath(*obj.Status.Artifact)
			t.Logf("artifact local path: %s", localPath)

			f, err := os.Open(localPath)
			g.Expect(err).ToNot(HaveOccurred())
			defer f.Close()

			// create a tmp directory to extract artifact
			tmp, err := os.MkdirTemp("", "ocirepository-test-")
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(tmp)

			err = tar.Untar(f, tmp, tar.WithMaxUntarSize(-1))
			g.Expect(err).ToNot(HaveOccurred())

			for _, af := range tt.assertArtifact {
				expectedFile := filepath.Join(tmp, af.expectedPath)
				g.Expect(expectedFile).To(BeAnExistingFile())

				f2, err := os.Open(expectedFile)
				g.Expect(err).ToNot(HaveOccurred())
				defer f2.Close()

				d, err := intdigest.Canonical.FromReader(f2)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(d.Encoded()).To(Equal(af.expectedChecksum))
			}

			// Check if the object status is valid
			condns := &conditionscheck.Conditions{NegativePolarity: ociRepositoryReadyCondition.NegativePolarity}
			checker := conditionscheck.NewChecker(testEnv.Client, condns)
			checker.WithT(g).CheckErr(ctx, obj)

			// kstatus client conformance check
			u, err := patch.ToUnstructured(obj)
			g.Expect(err).ToNot(HaveOccurred())
			res, err := kstatus.Compute(u)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(res.Status).To(Equal(kstatus.CurrentStatus))

			// Patch the object with reconcile request annotation.
			patchHelper, err := patch.NewHelper(obj, testEnv.Client)
			g.Expect(err).ToNot(HaveOccurred())
			annotations := map[string]string{
				meta.ReconcileRequestAnnotation: "now",
			}
			obj.SetAnnotations(annotations)
			g.Expect(patchHelper.Patch(ctx, obj)).ToNot(HaveOccurred())
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, obj); err != nil {
					return false
				}
				return obj.Status.LastHandledReconcileAt == "now"
			}, timeout).Should(BeTrue())

			// Wait for the object to be deleted
			g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())
			waitForSourceDeletion(ctx, g, obj)

			// Check if a suspended object gets deleted.
			obj = origObj.DeepCopy()
			testSuspendedObjectDeleteWithArtifact(ctx, g, obj)
		})
	}
}

func TestOCIRepository_Reconcile_MediaType(t *testing.T) {
	g := NewWithT(t)

	// Registry server with public images
	tmpDir := t.TempDir()
	regServer, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	if err != nil {
		g.Expect(err).ToNot(HaveOccurred())
	}
	t.Cleanup(func() {
		regServer.Close()
	})

	podinfoVersions, err := pushMultiplePodinfoImages(regServer.registryHost, true, "6.1.4", "6.1.5", "6.1.6")
	g.Expect(err).ToNot(HaveOccurred())

	tests := []struct {
		name      string
		url       string
		tag       string
		mediaType string
		wantErr   bool
	}{
		{
			name: "Works with no media type",
			url:  podinfoVersions["6.1.4"].url,
			tag:  podinfoVersions["6.1.4"].tag,
		},
		{
			name:      "Works with Flux CLI media type",
			url:       podinfoVersions["6.1.5"].url,
			tag:       podinfoVersions["6.1.5"].tag,
			mediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
		},
		{
			name:      "Fails with unknown media type",
			url:       podinfoVersions["6.1.6"].url,
			tag:       podinfoVersions["6.1.6"].tag,
			mediaType: "application/invalid.tar.gzip",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ns, err := testEnv.CreateNamespace(ctx, "ocirepository-mediatype-test")
			g.Expect(err).ToNot(HaveOccurred())
			defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "ocirepository-reconcile",
					Namespace:    ns.Name,
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL:      tt.url,
					Interval: metav1.Duration{Duration: 60 * time.Minute},
					Reference: &sourcev1.OCIRepositoryRef{
						Tag: tt.tag,
					},
					LayerSelector: &sourcev1.OCILayerSelector{
						MediaType: tt.mediaType,
					},
					Insecure: true,
				},
			}

			g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

			key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

			// Wait for the finalizer to be set
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, obj); err != nil {
					return false
				}
				return len(obj.Finalizers) > 0
			}, timeout).Should(BeTrue())

			// Wait for the object to be reconciled
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, obj); err != nil {
					return false
				}
				readyCondition := conditions.Get(obj, meta.ReadyCondition)
				return readyCondition != nil && !conditions.IsUnknown(obj, meta.ReadyCondition)
			}, timeout).Should(BeTrue())

			g.Expect(conditions.IsReady(obj)).To(BeIdenticalTo(!tt.wantErr))
			if tt.wantErr {
				g.Expect(conditions.Get(obj, meta.ReadyCondition).Message).Should(ContainSubstring("failed to find layer with media type"))
			}

			// Wait for the object to be deleted
			g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, obj); err != nil {
					return apierrors.IsNotFound(err)
				}
				return false
			}, timeout).Should(BeTrue())
		})
	}
}

func TestOCIRepository_reconcileSource_authStrategy(t *testing.T) {
	type secretOptions struct {
		username      string
		password      string
		includeSA     bool
		includeSecret bool
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(tlsCA)

	tests := []struct {
		name             string
		url              string
		registryOpts     registryOptions
		craneOpts        []crane.Option
		secretOpts       secretOptions
		tlsCertSecret    *corev1.Secret
		insecure         bool
		provider         string
		providerImg      string
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name:      "HTTP without basic auth",
			want:      sreconcile.ResultSuccess,
			craneOpts: []crane.Option{crane.Insecure},
			insecure:  true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
			},
		},
		{
			name: "HTTP with basic auth secret",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			insecure: true,
			craneOpts: []crane.Option{
				crane.WithAuth(&authn.Basic{
					Username: testRegistryUsername,
					Password: testRegistryPassword,
				}),
				crane.Insecure,
			},
			secretOpts: secretOptions{
				username:      testRegistryUsername,
				password:      testRegistryPassword,
				includeSecret: true,
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
			},
		},
		{
			name: "HTTP with serviceaccount",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			insecure: true,
			craneOpts: []crane.Option{
				crane.WithAuth(&authn.Basic{
					Username: testRegistryUsername,
					Password: testRegistryPassword,
				}),
				crane.Insecure,
			},
			secretOpts: secretOptions{
				username:  testRegistryUsername,
				password:  testRegistryPassword,
				includeSA: true,
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
			},
		},
		{
			name: "HTTP registry - basic auth with missing secret",
			want: sreconcile.ResultEmpty,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			insecure: true,
			wantErr:  true,
			craneOpts: []crane.Option{
				crane.WithAuth(&authn.Basic{
					Username: testRegistryUsername,
					Password: testRegistryPassword,
				}),
				crane.Insecure,
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIPullFailedReason, "%s", "failed to determine artifact digest"),
			},
		},
		{
			name:    "HTTP registry - basic auth with invalid secret",
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			insecure: true,
			craneOpts: []crane.Option{
				crane.WithAuth(&authn.Basic{
					Username: testRegistryUsername,
					Password: testRegistryPassword,
				}),
				crane.Insecure,
			},
			secretOpts: secretOptions{
				username:      "wrong-pass",
				password:      "wrong-pass",
				includeSecret: true,
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIPullFailedReason, "%s", "UNAUTHORIZED"),
			},
		},
		{
			name:     "HTTP registry - basic auth with invalid serviceaccount",
			want:     sreconcile.ResultEmpty,
			wantErr:  true,
			insecure: true,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			craneOpts: []crane.Option{
				crane.WithAuth(&authn.Basic{
					Username: testRegistryUsername,
					Password: testRegistryPassword,
				}),
				crane.Insecure,
			},
			secretOpts: secretOptions{
				username:  "wrong-pass",
				password:  "wrong-pass",
				includeSA: true,
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIPullFailedReason, "%s", "UNAUTHORIZED"),
			},
		},
		{
			name: "HTTPS with valid certfile",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withTLS: true,
			},
			craneOpts: []crane.Option{crane.WithTransport(&http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			}),
			},
			tlsCertSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{
					"ca.crt": tlsCA,
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "%s", "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "%s", "building artifact: new revision '<revision>' for '<url>'"),
			},
		},
		{
			name: "HTTPS with valid certfile using deprecated keys",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withTLS: true,
			},
			craneOpts: []crane.Option{crane.WithTransport(&http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			}),
			},
			tlsCertSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{
					"caFile": tlsCA,
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "%s", "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "%s", "building artifact: new revision '<revision>' for '<url>'"),
			},
		},
		{
			name:    "HTTPS without certfile",
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			registryOpts: registryOptions{
				withTLS: true,
			},
			craneOpts: []crane.Option{crane.WithTransport(&http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			}),
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIPullFailedReason, "%s", "failed to determine artifact digest"),
			},
		},
		{
			name:    "HTTPS with invalid certfile",
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			registryOpts: registryOptions{
				withTLS: true,
			},
			craneOpts: []crane.Option{crane.WithTransport(&http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			}),
			},
			tlsCertSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{
					"ca.crt": []byte("invalid"),
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "%s", "failed to parse CA certificate"),
			},
		},
		{
			name: "HTTPS with certfile using both caFile and ca.crt ignores caFile",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withTLS: true,
			},
			craneOpts: []crane.Option{crane.WithTransport(&http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			}),
			},
			tlsCertSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{
					"ca.crt": tlsCA,
					"caFile": []byte("invalid"),
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "%s", "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "%s", "building artifact: new revision '<revision>' for '<url>'"),
			},
		},
		{
			name:        "with contextual login provider",
			wantErr:     true,
			provider:    "aws",
			providerImg: "oci://123456789000.dkr.ecr.us-east-2.amazonaws.com/test",
			craneOpts: []crane.Option{
				crane.Insecure,
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "%s", "failed to get credential from"),
			},
		},
		{
			name: "secretRef takes precedence over provider",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			craneOpts: []crane.Option{
				crane.WithAuth(&authn.Basic{
					Username: testRegistryUsername,
					Password: testRegistryPassword,
				}),
				crane.Insecure,
			},
			secretOpts: secretOptions{
				username:      testRegistryUsername,
				password:      testRegistryPassword,
				includeSecret: true,
			},
			insecure: true,
			provider: "azure",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "%s", "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "%s", "building artifact: new revision '<revision>' for '<url>'"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithStatusSubresource(&sourcev1.OCIRepository{})

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-strategy-",
					Generation:   1,
				},
				Spec: sourcev1.OCIRepositorySpec{
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
				},
			}

			workspaceDir := t.TempDir()
			server, err := setupRegistryServer(ctx, workspaceDir, tt.registryOpts)
			g.Expect(err).NotTo(HaveOccurred())
			t.Cleanup(func() {
				server.Close()
			})

			img, err := createPodinfoImageFromTar("podinfo-6.1.6.tar", "6.1.6", server.registryHost, tt.craneOpts...)
			g.Expect(err).ToNot(HaveOccurred())
			obj.Spec.URL = img.url
			obj.Spec.Reference = &sourcev1.OCIRepositoryRef{
				Tag: img.tag,
			}

			if tt.provider != "" {
				obj.Spec.Provider = tt.provider
			}
			// If a provider specific image is provided, overwrite existing URL
			// set earlier. It'll fail but it's necessary to set them because
			// the login check expects the URLs to be of certain pattern.
			if tt.providerImg != "" {
				obj.Spec.URL = tt.providerImg
			}

			if tt.secretOpts.username != "" && tt.secretOpts.password != "" {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "auth-secretref",
					},
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						".dockerconfigjson": []byte(fmt.Sprintf(`{"auths": {%q: {"username": %q, "password": %q}}}`,
							server.registryHost, tt.secretOpts.username, tt.secretOpts.password)),
					},
				}
				clientBuilder.WithObjects(secret)

				if tt.secretOpts.includeSA {
					serviceAccount := &corev1.ServiceAccount{
						ObjectMeta: metav1.ObjectMeta{
							Name: "sa-ocitest",
						},
						ImagePullSecrets: []corev1.LocalObjectReference{{Name: secret.Name}},
					}
					clientBuilder.WithObjects(serviceAccount)
					obj.Spec.ServiceAccountName = serviceAccount.Name
				}

				if tt.secretOpts.includeSecret {
					obj.Spec.SecretRef = &meta.LocalObjectReference{
						Name: secret.Name,
					}
				}
			}

			if tt.tlsCertSecret != nil {
				clientBuilder.WithObjects(tt.tlsCertSecret)
				obj.Spec.CertSecretRef = &meta.LocalObjectReference{
					Name: tt.tlsCertSecret.Name,
				}
			}
			if tt.insecure {
				obj.Spec.Insecure = true
			}

			r := &OCIRepositoryReconciler{
				Client:        clientBuilder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
				patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
			}

			opts := makeRemoteOptions(ctx, makeTransport(tt.insecure), authn.DefaultKeychain, nil)
			ref, err := r.getArtifactRef(obj, opts)
			g.Expect(err).To(BeNil())

			assertConditions := tt.assertConditions
			for k := range assertConditions {
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<revision>", fmt.Sprintf("%s@%s", img.tag, img.digest.String()))
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", ref.String())
			}

			g.Expect(r.Client.Create(ctx, obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(ctx, obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			tmpDir := t.TempDir()
			got, err := r.reconcileSource(ctx, sp, obj, &meta.Artifact{}, tmpDir)
			if tt.wantErr {
				g.Expect(err).ToNot(BeNil())
			} else {
				g.Expect(err).To(BeNil())
			}
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func makeTransport(insecure bool) http.RoundTripper {
	transport := remote.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	return transport
}
func TestOCIRepository_CertSecret(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	regServer, err := setupRegistryServer(ctx, tmpDir, registryOptions{
		withTLS:            true,
		withClientCertAuth: true,
	})
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() {
		regServer.Close()
	})

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(tlsCA)
	clientTLSCert, err := tls.X509KeyPair(clientPublicKey, clientPrivateKey)
	g.Expect(err).ToNot(HaveOccurred())

	transport := http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientTLSCert},
	}
	pi, err := createPodinfoImageFromTar("podinfo-6.1.5.tar", "6.1.5", regServer.registryHost, []crane.Option{
		crane.WithTransport(transport),
	}...)
	g.Expect(err).NotTo(HaveOccurred())

	tlsSecretClientCert := corev1.Secret{
		Data: map[string][]byte{
			"caFile":   tlsCA,
			"certFile": clientPublicKey,
			"keyFile":  clientPrivateKey,
		},
	}

	tests := []struct {
		name                  string
		url                   string
		digest                gcrv1.Hash
		certSecret            *corev1.Secret
		expectreadyconition   bool
		expectedstatusmessage string
	}{
		{
			name:                  "test connection with CACert, Client Cert and Private Key",
			url:                   pi.url,
			digest:                pi.digest,
			certSecret:            &tlsSecretClientCert,
			expectreadyconition:   true,
			expectedstatusmessage: fmt.Sprintf("stored artifact for digest '%s'", pi.digest.String()),
		},
		{
			name:                  "test connection with no secret",
			url:                   pi.url,
			digest:                pi.digest,
			expectreadyconition:   false,
			expectedstatusmessage: "tls: failed to verify certificate: x509:",
		},
		{
			name:   "test connection with with incorrect private key",
			url:    pi.url,
			digest: pi.digest,
			certSecret: &corev1.Secret{
				Data: map[string][]byte{
					"caFile":   tlsCA,
					"certFile": clientPublicKey,
					"keyFile":  []byte("invalid-key"),
				},
			},
			expectreadyconition:   false,
			expectedstatusmessage: "failed to generate transport for '<url>': failed to parse TLS certificate and key: tls: failed to find any PEM data in key input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ns, err := testEnv.CreateNamespace(ctx, "ocirepository-test")
			g.Expect(err).ToNot(HaveOccurred())
			defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "ocirepository-test-resource",
					Namespace:    ns.Name,
					Generation:   1,
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL:       tt.url,
					Interval:  metav1.Duration{Duration: 60 * time.Minute},
					Reference: &sourcev1.OCIRepositoryRef{Digest: tt.digest.String()},
				},
			}

			if tt.certSecret != nil {
				tt.certSecret.ObjectMeta = metav1.ObjectMeta{
					GenerateName: "cert-secretref",
					Namespace:    ns.Name,
				}

				g.Expect(testEnv.CreateAndWait(ctx, tt.certSecret)).To(Succeed())
				defer func() { g.Expect(testEnv.Delete(ctx, tt.certSecret)).To(Succeed()) }()

				obj.Spec.CertSecretRef = &meta.LocalObjectReference{Name: tt.certSecret.Name}
			}

			g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

			key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

			resultobj := sourcev1.OCIRepository{}

			// Wait for the finalizer to be set
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, &resultobj); err != nil {
					return false
				}
				return len(resultobj.Finalizers) > 0
			}, timeout).Should(BeTrue())

			// Wait for the object to be ready
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, &resultobj); err != nil {
					return false
				}
				readyCondition := conditions.Get(&resultobj, meta.ReadyCondition)
				if readyCondition == nil || conditions.IsUnknown(&resultobj, meta.ReadyCondition) {
					return false
				}
				return obj.Generation == readyCondition.ObservedGeneration &&
					conditions.IsReady(&resultobj) == tt.expectreadyconition
			}, timeout).Should(BeTrue())

			tt.expectedstatusmessage = strings.ReplaceAll(tt.expectedstatusmessage, "<url>", pi.url)

			readyCondition := conditions.Get(&resultobj, meta.ReadyCondition)
			g.Expect(readyCondition.Message).Should(ContainSubstring(tt.expectedstatusmessage))

			// Wait for the object to be deleted
			g.Expect(testEnv.Delete(ctx, &resultobj)).To(Succeed())
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, &resultobj); err != nil {
					return apierrors.IsNotFound(err)
				}
				return false
			}, timeout).Should(BeTrue())
		})
	}
}

func TestOCIRepository_ProxySecret(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	regServer, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() {
		regServer.Close()
	})

	pi, err := createPodinfoImageFromTar("podinfo-6.1.5.tar", "6.1.5", regServer.registryHost)
	g.Expect(err).NotTo(HaveOccurred())

	proxyAddr, proxyPort := testproxy.New(t)

	tests := []struct {
		name                  string
		url                   string
		digest                gcrv1.Hash
		proxySecret           *corev1.Secret
		expectreadyconition   bool
		expectedstatusmessage string
	}{
		{
			name:   "test proxied connection",
			url:    pi.url,
			digest: pi.digest,
			proxySecret: &corev1.Secret{
				Data: map[string][]byte{
					"address": []byte(fmt.Sprintf("http://%s", proxyAddr)),
				},
			},
			expectreadyconition:   true,
			expectedstatusmessage: fmt.Sprintf("stored artifact for digest '%s'", pi.digest.String()),
		},
		{
			name:   "test proxy connection error",
			url:    pi.url,
			digest: pi.digest,
			proxySecret: &corev1.Secret{
				Data: map[string][]byte{
					"address": []byte(fmt.Sprintf("http://localhost:%d", proxyPort+1)),
				},
			},
			expectreadyconition:   false,
			expectedstatusmessage: "failed to pull artifact",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ns, err := testEnv.CreateNamespace(ctx, "ocirepository-test")
			g.Expect(err).ToNot(HaveOccurred())
			defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "ocirepository-test-resource",
					Namespace:    ns.Name,
					Generation:   1,
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL:       tt.url,
					Interval:  metav1.Duration{Duration: 60 * time.Minute},
					Reference: &sourcev1.OCIRepositoryRef{Digest: tt.digest.String()},
				},
			}

			if tt.proxySecret != nil {
				tt.proxySecret.ObjectMeta = metav1.ObjectMeta{
					GenerateName: "proxy-secretref",
					Namespace:    ns.Name,
				}

				g.Expect(testEnv.CreateAndWait(ctx, tt.proxySecret)).To(Succeed())
				defer func() { g.Expect(testEnv.Delete(ctx, tt.proxySecret)).To(Succeed()) }()

				obj.Spec.ProxySecretRef = &meta.LocalObjectReference{Name: tt.proxySecret.Name}
			}

			g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

			key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

			resultobj := sourcev1.OCIRepository{}

			// Wait for the finalizer to be set
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, &resultobj); err != nil {
					return false
				}
				return len(resultobj.Finalizers) > 0
			}, timeout).Should(BeTrue())

			// Wait for the object to be ready
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, &resultobj); err != nil {
					return false
				}
				readyCondition := conditions.Get(&resultobj, meta.ReadyCondition)
				if readyCondition == nil || conditions.IsUnknown(&resultobj, meta.ReadyCondition) {
					return false
				}
				return obj.Generation == readyCondition.ObservedGeneration &&
					conditions.IsReady(&resultobj) == tt.expectreadyconition
			}, timeout).Should(BeTrue())

			tt.expectedstatusmessage = strings.ReplaceAll(tt.expectedstatusmessage, "<url>", pi.url)

			readyCondition := conditions.Get(&resultobj, meta.ReadyCondition)
			g.Expect(readyCondition.Message).Should(ContainSubstring(tt.expectedstatusmessage))

			// Wait for the object to be deleted
			g.Expect(testEnv.Delete(ctx, &resultobj)).To(Succeed())
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, &resultobj); err != nil {
					return apierrors.IsNotFound(err)
				}
				return false
			}, timeout).Should(BeTrue())
		})
	}
}

func TestOCIRepository_reconcileSource_remoteReference(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	server, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() {
		server.Close()
	})

	podinfoVersions, err := pushMultiplePodinfoImages(server.registryHost, true, "6.1.4", "6.1.5", "6.1.6")
	g.Expect(err).ToNot(HaveOccurred())

	img6 := podinfoVersions["6.1.6"]
	img5 := podinfoVersions["6.1.5"]

	tests := []struct {
		name             string
		reference        *sourcev1.OCIRepositoryRef
		want             sreconcile.Result
		wantErr          bool
		wantRevision     string
		assertConditions []metav1.Condition
	}{
		{
			name:         "no reference (latest tag)",
			want:         sreconcile.ResultSuccess,
			wantRevision: fmt.Sprintf("latest@%s", img6.digest.String()),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision"),
			},
		},
		{
			name: "tag reference",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.6",
			},
			want:         sreconcile.ResultSuccess,
			wantRevision: fmt.Sprintf("%s@%s", img6.tag, img6.digest.String()),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision"),
			},
		},
		{
			name: "semver reference",
			reference: &sourcev1.OCIRepositoryRef{
				SemVer: ">= 6.1.5",
			},
			want:         sreconcile.ResultSuccess,
			wantRevision: fmt.Sprintf("%s@%s", img6.tag, img6.digest.String()),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision"),
			},
		},
		{
			name: "digest reference",
			reference: &sourcev1.OCIRepositoryRef{
				Digest: img6.digest.String(),
			},
			wantRevision: img6.digest.String(),
			want:         sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision"),
			},
		},
		{
			name: "invalid tag reference",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.0",
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIPullFailedReason, " MANIFEST_UNKNOWN"),
			},
		},
		{
			name: "invalid semver reference",
			reference: &sourcev1.OCIRepositoryRef{
				SemVer: "<= 6.1.0",
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.ReadOperationFailedReason, "failed to determine the artifact tag for 'oci://%s/podinfo': no match found for semver: <= 6.1.0", server.registryHost),
			},
		},
		{
			name: "invalid digest reference",
			reference: &sourcev1.OCIRepositoryRef{
				Digest: "invalid",
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIPullFailedReason, "failed to determine artifact digest"),
			},
		},
		{
			name: "semver should take precedence over tag",
			reference: &sourcev1.OCIRepositoryRef{
				SemVer: ">= 6.1.5",
				Tag:    "6.1.5",
			},
			want:         sreconcile.ResultSuccess,
			wantRevision: fmt.Sprintf("%s@%s", img6.tag, img6.digest.String()),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision"),
			},
		},
		{
			name: "digest should take precedence over semver",
			reference: &sourcev1.OCIRepositoryRef{
				Tag:    "6.1.6",
				SemVer: ">= 6.1.6",
				Digest: img5.digest.String(),
			},
			want:         sreconcile.ResultSuccess,
			wantRevision: img5.digest.String(),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision"),
			},
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&sourcev1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "checkout-strategy-",
					Generation:   1,
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL:      fmt.Sprintf("oci://%s/podinfo", server.registryHost),
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
					Insecure: true,
				},
			}

			if tt.reference != nil {
				obj.Spec.Reference = tt.reference
			}

			g.Expect(r.Client.Create(ctx, obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(ctx, obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			artifact := &meta.Artifact{}
			tmpDir := t.TempDir()
			got, err := r.reconcileSource(ctx, sp, obj, artifact, tmpDir)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(artifact.Revision).To(Equal(tt.wantRevision))
			}

			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestOCIRepository_reconcileSource_verifyOCISourceSignatureNotation(t *testing.T) {
	g := NewWithT(t)

	tests := []struct {
		name             string
		reference        *sourcev1.OCIRepositoryRef
		insecure         bool
		want             sreconcile.Result
		wantErr          bool
		wantErrMsg       string
		shouldSign       bool
		useDigest        bool
		addMultipleCerts bool
		provideNoCert    bool
		beforeFunc       func(obj *sourcev1.OCIRepository, tag, revision string)
		assertConditions []metav1.Condition
	}{
		{
			name: "signed image should pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			shouldSign: true,
			want:       sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
		},
		{
			name: "unsigned image should not pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.5",
			},
			wantErr:    true,
			useDigest:  true,
			wantErrMsg: "failed to verify the signature using provider 'notation': no signature is associated with \"<url>\"",
			want:       sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider '<provider>': no signature is associated with \"<url>\", make sure the artifact was signed successfully"),
			},
		},
		{
			name:      "verify failed before, removed from spec, remove condition",
			reference: &sourcev1.OCIRepositoryRef{Tag: "6.1.4"},
			beforeFunc: func(obj *sourcev1.OCIRepository, tag, revision string) {
				conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, "VerifyFailed", "fail msg")
				obj.Spec.Verify = nil
				obj.Status.Artifact = &meta.Artifact{Revision: fmt.Sprintf("%s@%s", tag, revision)}
			},
			want: sreconcile.ResultSuccess,
		},
		{
			name:       "same artifact, verified before, change in obj gen verify again",
			reference:  &sourcev1.OCIRepositoryRef{Tag: "6.1.4"},
			shouldSign: true,
			beforeFunc: func(obj *sourcev1.OCIRepository, tag, revision string) {
				obj.Status.Artifact = &meta.Artifact{Revision: fmt.Sprintf("%s@%s", tag, revision)}
				// Set Verified with old observed generation and different reason/message.
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Verified", "verified")
				// Set new object generation.
				obj.SetGeneration(3)
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
		},
		{
			name:       "no verify for already verified, verified condition remains the same",
			reference:  &sourcev1.OCIRepositoryRef{Tag: "6.1.4"},
			shouldSign: true,
			beforeFunc: func(obj *sourcev1.OCIRepository, tag, revision string) {
				// Artifact present and custom verified condition reason/message.
				obj.Status.Artifact = &meta.Artifact{Revision: fmt.Sprintf("%s@%s", tag, revision)}
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Verified", "verified")
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, "Verified", "verified"),
			},
		},
		{
			name: "signed image on an insecure registry passes verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.6",
			},
			shouldSign: true,
			insecure:   true,
			want:       sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
		},
		{
			name: "signed image on an insecure registry using digest as reference passes verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.6",
			},
			shouldSign: true,
			insecure:   true,
			useDigest:  true,
			want:       sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
		},
		{
			name: "verification level audit and correct trust identity should pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.6",
			},
			shouldSign:       true,
			insecure:         true,
			useDigest:        true,
			want:             sreconcile.ResultSuccess,
			addMultipleCerts: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
		},
		{
			name: "no cert provided should not pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.5",
			},
			wantErr:       true,
			useDigest:     true,
			provideNoCert: true,
			// no namespace but the namespace name should appear before the /notation-config
			wantErrMsg: "failed to verify the signature using provider 'notation': no certificates found in secret '/notation-config",
			want:       sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider '<provider>': no certificates found in secret '/notation-config"),
			},
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&sourcev1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	certTuple := testhelper.GetRSASelfSignedSigningCertTuple("notation self-signed certs for testing")
	certs := []*x509.Certificate{certTuple.Cert}

	signer, err := signer.New(certTuple.PrivateKey, certs)
	g.Expect(err).ToNot(HaveOccurred())

	policyDocument := trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:                  "test-statement-name",
				RegistryScopes:        []string{"*"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelStrict.Name, Override: map[trustpolicy.ValidationType]trustpolicy.ValidationAction{trustpolicy.TypeRevocation: trustpolicy.ActionSkip}},
				TrustStores:           []string{"ca:valid-trust-store"},
				TrustedIdentities:     []string{"*"},
			},
		},
	}

	tmpDir := t.TempDir()

	policy, err := json.Marshal(policyDocument)
	g.Expect(err).NotTo(HaveOccurred())

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "valid-trust-store",
			Generation: 1,
		},
		Data: map[string][]byte{
			"ca.crt": tlsCA,
		},
	}

	g.Expect(r.Create(ctx, caSecret)).ToNot(HaveOccurred())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			workspaceDir := t.TempDir()
			server, err := setupRegistryServer(ctx, workspaceDir, registryOptions{
				withTLS: !tt.insecure,
			})
			g.Expect(err).NotTo(HaveOccurred())
			t.Cleanup(func() {
				server.Close()
			})

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "verify-oci-source-signature-",
					Generation:   1,
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL: fmt.Sprintf("oci://%s/podinfo", server.registryHost),
					Verify: &sourcev1.OCIRepositoryVerification{
						Provider: "notation",
					},
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
				},
			}

			data := map[string][]byte{}

			if tt.addMultipleCerts {
				data["a.crt"] = testhelper.GetRSASelfSignedSigningCertTuple("a not used for signing").Cert.Raw
				data["b.crt"] = testhelper.GetRSASelfSignedSigningCertTuple("b not used for signing").Cert.Raw
				data["c.crt"] = testhelper.GetRSASelfSignedSigningCertTuple("c not used for signing").Cert.Raw
			}

			if !tt.provideNoCert {
				data["notation.crt"] = certTuple.Cert.Raw
			}

			data["trustpolicy.json"] = policy

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "notation-config-",
				},
				Data: data,
			}

			g.Expect(r.Create(ctx, secret)).NotTo(HaveOccurred())

			if tt.insecure {
				obj.Spec.Insecure = true
			} else {
				obj.Spec.CertSecretRef = &meta.LocalObjectReference{
					Name: "valid-trust-store",
				}
			}

			obj.Spec.Verify.SecretRef = &meta.LocalObjectReference{Name: secret.GetName()}

			if tt.reference != nil {
				obj.Spec.Reference = tt.reference
			}

			podinfoVersions, err := pushMultiplePodinfoImages(server.registryHost, tt.insecure, tt.reference.Tag)
			g.Expect(err).ToNot(HaveOccurred())

			if tt.useDigest {
				obj.Spec.Reference.Digest = podinfoVersions[tt.reference.Tag].digest.String()
			}

			keychain, err := r.keychain(ctx, obj)
			if err != nil {
				g.Expect(err).ToNot(HaveOccurred())
			}

			opts := makeRemoteOptions(ctx, makeTransport(true), keychain, nil)

			artifactRef, err := r.getArtifactRef(obj, opts)
			g.Expect(err).ToNot(HaveOccurred())

			if tt.shouldSign {
				remoteRepo, err := oras.NewRepository(artifactRef.String())
				g.Expect(err).ToNot(HaveOccurred())

				if tt.insecure {
					remoteRepo.PlainHTTP = true
				}

				repo := registry.NewRepository(remoteRepo)

				signatureMediaType := cose.MediaTypeEnvelope

				signOptions := notation.SignOptions{
					SignerSignOptions: notation.SignerSignOptions{
						SignatureMediaType: signatureMediaType,
					},
					ArtifactReference: artifactRef.String(),
				}

				_, err = notation.Sign(ctx, signer, repo, signOptions)
				g.Expect(err).ToNot(HaveOccurred())
			}

			image := podinfoVersions[tt.reference.Tag]
			assertConditions := tt.assertConditions
			for k := range assertConditions {
				if tt.useDigest {
					assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<revision>", image.digest.String())
				} else {
					assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<revision>", fmt.Sprintf("%s@%s", tt.reference.Tag, image.digest.String()))
				}
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", artifactRef.String())
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<provider>", "notation")
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj, image.tag, image.digest.String())
			}

			g.Expect(r.Client.Create(ctx, obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(ctx, obj)).ToNot(HaveOccurred())
				g.Expect(r.Delete(ctx, secret)).NotTo(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			artifact := &meta.Artifact{}
			got, err := r.reconcileSource(ctx, sp, obj, artifact, tmpDir)
			if tt.wantErr {
				tt.wantErrMsg = strings.ReplaceAll(tt.wantErrMsg, "<url>", artifactRef.String())
				g.Expect(err).ToNot(BeNil())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErrMsg))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestOCIRepository_reconcileSource_verifyOCISourceTrustPolicyNotation(t *testing.T) {
	g := NewWithT(t)

	tests := []struct {
		name                  string
		reference             *sourcev1.OCIRepositoryRef
		signatureVerification trustpolicy.SignatureVerification
		trustedIdentities     []string
		trustStores           []string
		want                  sreconcile.Result
		wantErr               bool
		wantErrMsg            string
		useDigest             bool
		usePolicyJson         bool
		provideNoPolicy       bool
		policyJson            string
		beforeFunc            func(obj *sourcev1.OCIRepository, tag, revision string)
		assertConditions      []metav1.Condition
	}{
		{
			name: "verification level audit and incorrect trust identity should fail verification but not error",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			signatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelAudit.Name},
			trustedIdentities:     []string{"x509.subject: C=US, ST=WA, L=Seattle, O=Notary, CN=example.com"},
			trustStores:           []string{"ca:valid-trust-store"},
			want:                  sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
			},
		},
		{
			name: "verification level permissive and incorrect trust identity should fail verification and error",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			signatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelPermissive.Name},
			trustedIdentities:     []string{"x509.subject: C=US, ST=WA, L=Seattle, O=Notary, CN=example.com"},
			trustStores:           []string{"ca:valid-trust-store"},
			useDigest:             true,
			want:                  sreconcile.ResultEmpty,
			wantErr:               true,
			wantErrMsg:            "failed to verify the signature using provider 'notation': signature verification failed\nfailed to verify signature with digest <sigrevision>, signing certificate from the digital signature does not match the X.509 trusted identities [map[\"C\":\"US\" \"CN\":\"example.com\" \"L\":\"Seattle\" \"O\":\"Notary\" \"ST\":\"WA\"]] defined in the trust policy \"test-statement-name\"",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider 'notation': signature verification failed\nfailed to verify signature with digest <sigrevision>, signing certificate from the digital signature does not match the X.509 trusted identities [map[\"C\":\"US\" \"CN\":\"example.com\" \"L\":\"Seattle\" \"O\":\"Notary\" \"ST\":\"WA\"]] defined in the trust policy \"test-statement-name\""),
			},
		},
		{
			name: "verification level permissive and correct trust identity should pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			signatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelPermissive.Name},
			trustedIdentities:     []string{"*"},
			trustStores:           []string{"ca:valid-trust-store"},
			want:                  sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
		},
		{
			name: "verification level audit and correct trust identity should pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			signatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelAudit.Name},
			trustedIdentities:     []string{"*"},
			trustStores:           []string{"ca:valid-trust-store"},
			want:                  sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
		},
		{
			name: "verification level skip and should not be marked as verified",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			signatureVerification: trustpolicy.SignatureVerification{VerificationLevel: trustpolicy.LevelSkip.Name},
			trustedIdentities:     []string{},
			want:                  sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
			},
		},
		{
			name: "valid json but empty policy json should fail verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			usePolicyJson: true,
			policyJson:    "{}",
			wantErr:       true,
			wantErrMsg:    "trust policy document has empty version",
			want:          sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "trust policy document has empty version, version must be specified"),
			},
		},
		{
			name: "empty string should fail verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			usePolicyJson: true,
			policyJson:    "",
			wantErr:       true,
			wantErrMsg:    fmt.Sprintf("error occurred while parsing %s: unexpected end of JSON input", snotation.DefaultTrustPolicyKey),
			want:          sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "error occurred while parsing %s: unexpected end of JSON input", snotation.DefaultTrustPolicyKey),
			},
		},
		{
			name: "invalid character in string should fail verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			usePolicyJson: true,
			policyJson:    "{\"version\": \"1.0\u000A\", \"trust_policies\": []}",
			wantErr:       true,
			wantErrMsg:    fmt.Sprintf("error occurred while parsing %s: invalid character '\\n' in string literal", snotation.DefaultTrustPolicyKey),
			want:          sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "error occurred while parsing %s: invalid character '\\n' in string literal", snotation.DefaultTrustPolicyKey),
			},
		},
		{
			name: "empty string should fail verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			provideNoPolicy: true,
			wantErr:         true,
			wantErrMsg:      fmt.Sprintf("failed to verify the signature using provider 'notation': '%s' not found in secret '/notation", snotation.DefaultTrustPolicyKey),
			want:            sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider 'notation': '%s' not found in secret '/notation", snotation.DefaultTrustPolicyKey),
			},
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&sourcev1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	certTuple := testhelper.GetRSASelfSignedSigningCertTuple("notation self-signed certs for testing")
	certs := []*x509.Certificate{certTuple.Cert}

	signer, err := signer.New(certTuple.PrivateKey, certs)
	g.Expect(err).ToNot(HaveOccurred())

	tmpDir := t.TempDir()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			workspaceDir := t.TempDir()
			server, err := setupRegistryServer(ctx, workspaceDir, registryOptions{})
			g.Expect(err).NotTo(HaveOccurred())
			t.Cleanup(func() {
				server.Close()
			})

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "verify-oci-source-signature-",
					Generation:   1,
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL: fmt.Sprintf("oci://%s/podinfo", server.registryHost),
					Verify: &sourcev1.OCIRepositoryVerification{
						Provider: "notation",
					},
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
				},
			}

			var policy []byte

			if !tt.usePolicyJson {
				policyDocument := trustpolicy.Document{
					Version: "1.0",
					TrustPolicies: []trustpolicy.TrustPolicy{
						{
							Name:                  "test-statement-name",
							RegistryScopes:        []string{"*"},
							SignatureVerification: tt.signatureVerification,
							TrustStores:           tt.trustStores,
							TrustedIdentities:     tt.trustedIdentities,
						},
					},
				}

				policy, err = json.Marshal(policyDocument)
				g.Expect(err).NotTo(HaveOccurred())
			} else {
				policy = []byte(tt.policyJson)
			}

			data := map[string][]byte{}

			if !tt.provideNoPolicy {
				data["trustpolicy.json"] = policy
			}

			data["notation.crt"] = certTuple.Cert.Raw

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "notation-",
				},
				Data: data,
			}

			g.Expect(r.Create(ctx, secret)).NotTo(HaveOccurred())

			obj.Spec.Insecure = true

			obj.Spec.Verify.SecretRef = &meta.LocalObjectReference{Name: secret.GetName()}

			if tt.reference != nil {
				obj.Spec.Reference = tt.reference
			}

			podinfoVersions, err := pushMultiplePodinfoImages(server.registryHost, true, tt.reference.Tag)
			g.Expect(err).ToNot(HaveOccurred())

			if tt.useDigest {
				obj.Spec.Reference.Digest = podinfoVersions[tt.reference.Tag].digest.String()
			}

			keychain, err := r.keychain(ctx, obj)
			if err != nil {
				g.Expect(err).ToNot(HaveOccurred())
			}

			opts := makeRemoteOptions(ctx, makeTransport(true), keychain, nil)

			artifactRef, err := r.getArtifactRef(obj, opts)
			g.Expect(err).ToNot(HaveOccurred())

			remoteRepo, err := oras.NewRepository(artifactRef.String())
			g.Expect(err).ToNot(HaveOccurred())

			remoteRepo.PlainHTTP = true

			repo := registry.NewRepository(remoteRepo)

			signatureMediaType := cose.MediaTypeEnvelope

			signOptions := notation.SignOptions{
				SignerSignOptions: notation.SignerSignOptions{
					SignatureMediaType: signatureMediaType,
				},
				ArtifactReference: artifactRef.String(),
			}

			_, err = notation.Sign(ctx, signer, repo, signOptions)
			g.Expect(err).ToNot(HaveOccurred())

			image := podinfoVersions[tt.reference.Tag]
			signatureDigest := ""

			artifactDescriptor, err := repo.Resolve(ctx, image.tag)
			g.Expect(err).ToNot(HaveOccurred())
			_ = repo.ListSignatures(ctx, artifactDescriptor, func(signatureManifests []ocispec.Descriptor) error {
				g.Expect(len(signatureManifests)).Should(Equal(1))
				signatureDigest = signatureManifests[0].Digest.String()
				return nil
			})

			assertConditions := tt.assertConditions
			for k := range assertConditions {
				if tt.useDigest {
					assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<revision>", image.digest.String())
				} else {
					assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<revision>", fmt.Sprintf("%s@%s", tt.reference.Tag, image.digest.String()))
				}

				if signatureDigest != "" {
					assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<sigrevision>", signatureDigest)
				}
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", artifactRef.String())
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<provider>", "notation")
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj, image.tag, image.digest.String())
			}

			g.Expect(r.Client.Create(ctx, obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(ctx, obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			artifact := &meta.Artifact{}
			got, err := r.reconcileSource(ctx, sp, obj, artifact, tmpDir)
			g.Expect(r.Delete(ctx, secret)).NotTo(HaveOccurred())
			if tt.wantErr {
				tt.wantErrMsg = strings.ReplaceAll(tt.wantErrMsg, "<url>", artifactRef.String())
				if signatureDigest != "" {
					tt.wantErrMsg = strings.ReplaceAll(tt.wantErrMsg, "<sigrevision>", signatureDigest)
				}
				g.Expect(err).ToNot(BeNil())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErrMsg))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestOCIRepository_reconcileSource_verifyOCISourceSignatureCosign(t *testing.T) {
	g := NewWithT(t)

	tests := []struct {
		name             string
		reference        *sourcev1.OCIRepositoryRef
		insecure         bool
		want             sreconcile.Result
		wantErr          bool
		wantErrMsg       string
		shouldSign       bool
		keyless          bool
		beforeFunc       func(obj *sourcev1.OCIRepository, tag, revision string)
		assertConditions []metav1.Condition
	}{
		{
			name: "signed image should pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			shouldSign: true,
			want:       sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
		},
		{
			name: "unsigned image should not pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.5",
			},
			wantErr:    true,
			wantErrMsg: "failed to verify the signature using provider 'cosign': no matching signatures were found for '<url>'",
			want:       sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider '<provider>': no matching signatures were found for '<url>'"),
			},
		},
		{
			name: "unsigned image should not pass keyless verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.5",
			},
			wantErr: true,
			want:    sreconcile.ResultEmpty,
			keyless: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider '<provider> keyless': no signatures found"),
			},
		},
		{
			name:      "verify failed before, removed from spec, remove condition",
			reference: &sourcev1.OCIRepositoryRef{Tag: "6.1.4"},
			beforeFunc: func(obj *sourcev1.OCIRepository, tag, revision string) {
				conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, "VerifyFailed", "fail msg")
				obj.Spec.Verify = nil
				obj.Status.Artifact = &meta.Artifact{Revision: fmt.Sprintf("%s@%s", tag, revision)}
			},
			want: sreconcile.ResultSuccess,
		},
		{
			name:       "same artifact, verified before, change in obj gen verify again",
			reference:  &sourcev1.OCIRepositoryRef{Tag: "6.1.4"},
			shouldSign: true,
			beforeFunc: func(obj *sourcev1.OCIRepository, tag, revision string) {
				obj.Status.Artifact = &meta.Artifact{Revision: fmt.Sprintf("%s@%s", tag, revision)}
				// Set Verified with old observed generation and different reason/message.
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Verified", "verified")
				// Set new object generation.
				obj.SetGeneration(3)
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
		},
		{
			name:       "no verify for already verified, verified condition remains the same",
			reference:  &sourcev1.OCIRepositoryRef{Tag: "6.1.4"},
			shouldSign: true,
			beforeFunc: func(obj *sourcev1.OCIRepository, tag, revision string) {
				// Artifact present and custom verified condition reason/message.
				obj.Status.Artifact = &meta.Artifact{Revision: fmt.Sprintf("%s@%s", tag, revision)}
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Verified", "verified")
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, "Verified", "verified"),
			},
		},
		{
			name: "signed image on an insecure registry passes verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.6",
			},
			shouldSign: true,
			insecure:   true,
			want:       sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&sourcev1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	pf := func(b bool) ([]byte, error) {
		return []byte("cosign-password"), nil
	}

	keys, err := cosign.GenerateKeyPair(pf)
	g.Expect(err).ToNot(HaveOccurred())

	tmpDir := t.TempDir()
	err = os.WriteFile(path.Join(tmpDir, "cosign.key"), keys.PrivateBytes, 0600)
	g.Expect(err).ToNot(HaveOccurred())

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cosign-key",
		},
		Data: map[string][]byte{
			"cosign.pub": keys.PublicBytes,
		}}

	g.Expect(r.Create(ctx, secret)).NotTo(HaveOccurred())

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "ca-cert-cosign",
			Generation: 1,
		},
		Data: map[string][]byte{
			"ca.crt": tlsCA,
		},
	}

	g.Expect(r.Create(ctx, caSecret)).ToNot(HaveOccurred())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			workspaceDir := t.TempDir()
			regOpts := registryOptions{
				withTLS: !tt.insecure,
			}
			server, err := setupRegistryServer(ctx, workspaceDir, regOpts)
			g.Expect(err).NotTo(HaveOccurred())
			t.Cleanup(func() {
				server.Close()
			})

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "verify-oci-source-signature-",
					Generation:   1,
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL: fmt.Sprintf("oci://%s/podinfo", server.registryHost),
					Verify: &sourcev1.OCIRepositoryVerification{
						Provider: "cosign",
					},
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
				},
			}

			if tt.insecure {
				obj.Spec.Insecure = true
			} else {
				obj.Spec.CertSecretRef = &meta.LocalObjectReference{
					Name: "ca-cert-cosign",
				}
			}

			if !tt.keyless {
				obj.Spec.Verify.SecretRef = &meta.LocalObjectReference{Name: "cosign-key"}
			}

			if tt.reference != nil {
				obj.Spec.Reference = tt.reference
			}

			podinfoVersions, err := pushMultiplePodinfoImages(server.registryHost, tt.insecure, tt.reference.Tag)
			g.Expect(err).ToNot(HaveOccurred())

			keychain, err := r.keychain(ctx, obj)
			if err != nil {
				g.Expect(err).ToNot(HaveOccurred())
			}

			opts := makeRemoteOptions(ctx, makeTransport(true), keychain, nil)

			artifactRef, err := r.getArtifactRef(obj, opts)
			g.Expect(err).ToNot(HaveOccurred())

			if tt.shouldSign {
				ko := coptions.KeyOpts{
					KeyRef:   path.Join(tmpDir, "cosign.key"),
					PassFunc: pf,
				}

				ro := &coptions.RootOptions{
					Timeout: timeout,
				}
				err = sign.SignCmd(ro, ko, coptions.SignOptions{
					Upload:           true,
					SkipConfirmation: true,
					TlogUpload:       false,

					Registry: coptions.RegistryOptions{Keychain: keychain, AllowInsecure: true, AllowHTTPRegistry: tt.insecure},
				}, []string{artifactRef.String()})

				g.Expect(err).ToNot(HaveOccurred())
			}

			image := podinfoVersions[tt.reference.Tag]
			assertConditions := tt.assertConditions
			for k := range assertConditions {
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<revision>", fmt.Sprintf("%s@%s", tt.reference.Tag, image.digest.String()))
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", artifactRef.String())
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<provider>", "cosign")
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj, image.tag, image.digest.String())
			}

			g.Expect(r.Client.Create(ctx, obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(ctx, obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			artifact := &meta.Artifact{}
			got, err := r.reconcileSource(ctx, sp, obj, artifact, tmpDir)
			if tt.wantErr {
				tt.wantErrMsg = strings.ReplaceAll(tt.wantErrMsg, "<url>", artifactRef.String())
				g.Expect(err).ToNot(BeNil())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErrMsg))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestOCIRepository_reconcileSource_verifyOCISourceSignature_keyless(t *testing.T) {
	tests := []struct {
		name             string
		reference        *sourcev1.OCIRepositoryRef
		want             sreconcile.Result
		wantErr          bool
		wantErrMsg       string
		beforeFunc       func(obj *sourcev1.OCIRepository)
		assertConditions []metav1.Condition
		revision         string
	}{
		{
			name: "signed image with no identity matching specified should pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.5.1",
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
			revision: "6.5.1@sha256:049fff8f9c92abba8615c6c3dcf9d10d30082213f6fe86c9305257f806c31e31",
		},
		{
			name: "signed image with correct subject and issuer should pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.5.1",
			},
			want: sreconcile.ResultSuccess,
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.Verify.MatchOIDCIdentity = []sourcev1.OIDCIdentityMatch{
					{

						Subject: "^https://github.com/stefanprodan/podinfo.*$",
						Issuer:  "^https://token.actions.githubusercontent.com$",
					},
				}
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
			revision: "6.5.1@sha256:049fff8f9c92abba8615c6c3dcf9d10d30082213f6fe86c9305257f806c31e31",
		},
		{
			name: "signed image with both incorrect and correct identity matchers should pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.5.1",
			},
			want: sreconcile.ResultSuccess,
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.Verify.MatchOIDCIdentity = []sourcev1.OIDCIdentityMatch{
					{
						Subject: "intruder",
						Issuer:  "^https://honeypot.com$",
					},
					{

						Subject: "^https://github.com/stefanprodan/podinfo.*$",
						Issuer:  "^https://token.actions.githubusercontent.com$",
					},
				}
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <revision>"),
			},
			revision: "6.5.1@sha256:049fff8f9c92abba8615c6c3dcf9d10d30082213f6fe86c9305257f806c31e31",
		},
		{
			name: "signed image with incorrect subject and issuer should not pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.5.1",
			},
			wantErr: true,
			want:    sreconcile.ResultEmpty,
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.Verify.MatchOIDCIdentity = []sourcev1.OIDCIdentityMatch{
					{
						Subject: "intruder",
						Issuer:  "^https://honeypot.com$",
					},
				}
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider '<provider> keyless': no matching signatures: none of the expected identities matched what was in the certificate"),
			},
			revision: "6.5.1@sha256:049fff8f9c92abba8615c6c3dcf9d10d30082213f6fe86c9305257f806c31e31",
		},
		{
			name: "unsigned image should not pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.0",
			},
			wantErr: true,
			want:    sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider '<provider> keyless': no signatures found"),
			},
			revision: "6.1.0@sha256:3816fe9636a297f0c934b1fa0f46fe4c068920375536ac2803604adfb4c55894",
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&sourcev1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "verify-oci-source-signature-",
					Generation:   1,
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL: "oci://ghcr.io/stefanprodan/manifests/podinfo",
					Verify: &sourcev1.OCIRepositoryVerification{
						Provider: "cosign",
					},
					Interval:  metav1.Duration{Duration: interval},
					Timeout:   &metav1.Duration{Duration: timeout},
					Reference: tt.reference,
				},
			}
			url := strings.TrimPrefix(obj.Spec.URL, "oci://") + ":" + tt.reference.Tag

			assertConditions := tt.assertConditions
			for k := range assertConditions {
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<revision>", tt.revision)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", url)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<provider>", "cosign")
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			g.Expect(r.Client.Create(ctx, obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(ctx, obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			artifact := &meta.Artifact{}
			got, err := r.reconcileSource(ctx, sp, obj, artifact, t.TempDir())
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
				tt.wantErrMsg = strings.ReplaceAll(tt.wantErrMsg, "<url>", url)
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErrMsg))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}

func TestOCIRepository_reconcileSource_noop(t *testing.T) {
	g := NewWithT(t)

	testRevision := "6.1.5@sha256:8e4057c22d531d40e12b065443cb0d80394b7257c4dc557cb1fbd4dce892b86d"

	tmpDir := t.TempDir()
	server, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() {
		server.Close()
	})

	_, err = pushMultiplePodinfoImages(server.registryHost, true, "6.1.5")
	g.Expect(err).ToNot(HaveOccurred())

	// NOTE: The following verifies if it was a noop run by checking the
	// artifact metadata which is unknown unless the image is pulled.

	tests := []struct {
		name       string
		beforeFunc func(obj *sourcev1.OCIRepository)
		afterFunc  func(g *WithT, artifact *meta.Artifact)
	}{
		{
			name: "full reconcile - no existing artifact",
			afterFunc: func(g *WithT, artifact *meta.Artifact) {
				g.Expect(artifact.Metadata).ToNot(BeEmpty())
			},
		},
		{
			name: "noop - artifact revisions match",
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &meta.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *meta.Artifact) {
				g.Expect(artifact.Metadata).To(BeEmpty())
			},
		},
		{
			name: "full reconcile - same rev, unobserved ignore",
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.ObservedIgnore = ptr.To("aaa")
				obj.Status.Artifact = &meta.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *meta.Artifact) {
				g.Expect(artifact.Metadata).ToNot(BeEmpty())
			},
		},
		{
			name: "noop - same rev, observed ignore",
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.Ignore = ptr.To("aaa")
				obj.Status.ObservedIgnore = ptr.To("aaa")
				obj.Status.Artifact = &meta.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *meta.Artifact) {
				g.Expect(artifact.Metadata).To(BeEmpty())
			},
		},
		{
			name: "full reconcile - same rev, unobserved layer selector",
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Operation: sourcev1.OCILayerCopy,
				}
				obj.Status.Artifact = &meta.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *meta.Artifact) {
				g.Expect(artifact.Metadata).ToNot(BeEmpty())
			},
		},
		{
			name: "noop - same rev, observed layer selector",
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Operation: sourcev1.OCILayerCopy,
				}
				obj.Status.ObservedLayerSelector = &sourcev1.OCILayerSelector{
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Operation: sourcev1.OCILayerCopy,
				}
				obj.Status.Artifact = &meta.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *meta.Artifact) {
				g.Expect(artifact.Metadata).To(BeEmpty())
			},
		},
		{
			name: "full reconcile - same rev, observed layer selector changed",
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Operation: sourcev1.OCILayerExtract,
				}
				obj.Status.ObservedLayerSelector = &sourcev1.OCILayerSelector{
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Operation: sourcev1.OCILayerCopy,
				}
				obj.Status.Artifact = &meta.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *meta.Artifact) {
				g.Expect(artifact.Metadata).ToNot(BeEmpty())
			},
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&sourcev1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "noop-",
					Generation:   1,
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL:       fmt.Sprintf("oci://%s/podinfo", server.registryHost),
					Reference: &sourcev1.OCIRepositoryRef{Tag: "6.1.5"},
					Interval:  metav1.Duration{Duration: interval},
					Timeout:   &metav1.Duration{Duration: timeout},
					Insecure:  true,
				},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			g.Expect(r.Client.Create(ctx, obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(ctx, obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			artifact := &meta.Artifact{}
			tmpDir := t.TempDir()
			got, err := r.reconcileSource(ctx, sp, obj, artifact, tmpDir)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).To(Equal(sreconcile.ResultSuccess))

			if tt.afterFunc != nil {
				tt.afterFunc(g, artifact)
			}
		})
	}
}

func TestOCIRepository_reconcileArtifact(t *testing.T) {
	tests := []struct {
		name             string
		targetPath       string
		artifact         *meta.Artifact
		beforeFunc       func(obj *sourcev1.OCIRepository)
		want             sreconcile.Result
		wantErr          bool
		assertArtifact   *meta.Artifact
		assertPaths      []string
		assertConditions []metav1.Condition
		afterFunc        func(g *WithT, obj *sourcev1.OCIRepository)
	}{
		{
			name:       "Archiving Artifact creates correct files and condition",
			targetPath: "testdata/oci/repository",
			artifact: &meta.Artifact{
				Revision: "revision",
			},
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision")
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *sourcev1.OCIRepository) {
				g.Expect(obj.Status.Artifact.Digest).To(Equal("sha256:6a5bd135a816ec0ad246c41cfdd87629e40ef6520001aeb2d0118a703abe9e7a"))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "Artifact with source ignore",
			targetPath: "testdata/oci/repository",
			artifact:   &meta.Artifact{Revision: "revision"},
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.Ignore = ptr.To("foo.txt")
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *sourcev1.OCIRepository) {
				g.Expect(obj.Status.Artifact.Digest).To(Equal("sha256:9102e9c8626e48821a91a4963436f1673cd85f8fb3deb843c992f85b995c38ea"))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name: "No status changes if artifact is already present",
			artifact: &meta.Artifact{
				Revision: "revision",
			},
			targetPath: "testdata/oci/repository",
			want:       sreconcile.ResultSuccess,
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &meta.Artifact{
					Revision: "revision",
				}
			},
			assertArtifact: &meta.Artifact{
				Revision: "revision",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "Artifact already present, unobserved ignore, rebuild artifact",
			targetPath: "testdata/oci/repository",
			artifact: &meta.Artifact{
				Revision: "revision",
			},
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "revision"}
				obj.Spec.Ignore = ptr.To("aaa")
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *sourcev1.OCIRepository) {
				g.Expect(*obj.Status.ObservedIgnore).To(Equal("aaa"))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "Artifact already present, unobserved layer selector, rebuild artifact",
			targetPath: "testdata/oci/repository",
			artifact: &meta.Artifact{
				Revision: "revision",
			},
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{MediaType: "foo"}
				obj.Status.Artifact = &meta.Artifact{Revision: "revision"}
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *sourcev1.OCIRepository) {
				g.Expect(obj.Status.ObservedLayerSelector.MediaType).To(Equal("foo"))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "Artifact already present, observed layer selector changed, rebuild artifact",
			targetPath: "testdata/oci/repository",
			artifact: &meta.Artifact{
				Revision: "revision",
				Path:     "foo.txt",
			},
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{
					MediaType: "foo",
					Operation: sourcev1.OCILayerCopy,
				}
				obj.Status.Artifact = &meta.Artifact{Revision: "revision"}
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *sourcev1.OCIRepository) {
				g.Expect(obj.Status.ObservedLayerSelector.MediaType).To(Equal("foo"))
				g.Expect(obj.Status.ObservedLayerSelector.Operation).To(Equal(sourcev1.OCILayerCopy))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "Artifact already present, observed ignore and layer selector, up-to-date",
			targetPath: "testdata/oci/repository",
			artifact: &meta.Artifact{
				Revision: "revision",
			},
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.Ignore = ptr.To("aaa")
				obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{MediaType: "foo"}
				obj.Status.Artifact = &meta.Artifact{Revision: "revision"}
				obj.Status.ObservedIgnore = ptr.To("aaa")
				obj.Status.ObservedLayerSelector = &sourcev1.OCILayerSelector{MediaType: "foo"}
			},
			want: sreconcile.ResultSuccess,
			assertArtifact: &meta.Artifact{
				Revision: "revision",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "target path doesn't exist",
			targetPath: "testdata/oci/non-existent",
			want:       sreconcile.ResultEmpty,
			wantErr:    true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.StorageOperationFailedCondition, sourcev1.StatOperationFailedReason, "failed to stat source path: "),
			},
		},
		{
			name:       "target path is a file",
			targetPath: "testdata/oci/repository/foo.txt",
			want:       sreconcile.ResultEmpty,
			wantErr:    true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.StorageOperationFailedCondition, sourcev1.InvalidPathReason, "source path 'testdata/oci/repository/foo.txt' is not a directory"),
			},
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&sourcev1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			_ = resetChmod(tt.targetPath, 0o755, 0o644)

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "reconcile-artifact-",
					Generation:   1,
				},
			}
			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			artifact := &meta.Artifact{}
			if tt.artifact != nil {
				artifact = tt.artifact
			}

			g.Expect(r.Client.Create(ctx, obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(ctx, obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileArtifact(ctx, sp, obj, artifact, tt.targetPath)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}

			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			if tt.assertArtifact != nil {
				g.Expect(obj.Status.Artifact).To(MatchArtifact(tt.artifact))
			}

			if tt.afterFunc != nil {
				tt.afterFunc(g, obj)
			}

			for _, p := range tt.assertPaths {
				localPath := testStorage.LocalPath(*obj.GetArtifact())
				p = filepath.Join(filepath.Dir(localPath), p)
				_, err := os.Lstat(p)
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

func TestOCIRepository_getArtifactRef(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	server, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	g.Expect(err).ToNot(HaveOccurred())
	t.Cleanup(func() {
		server.Close()
	})

	imgs, err := pushMultiplePodinfoImages(server.registryHost, true,
		"6.1.4",
		"6.1.5-beta.1",
		"6.1.5-rc.1",
		"6.1.5",
		"6.1.6-rc.1",
		"6.1.6",
	)
	g.Expect(err).ToNot(HaveOccurred())

	tests := []struct {
		name      string
		url       string
		reference *sourcev1.OCIRepositoryRef
		wantErr   bool
		want      string
	}{
		{
			name: "valid url with no reference",
			url:  "oci://ghcr.io/stefanprodan/charts",
			want: "ghcr.io/stefanprodan/charts:latest",
		},
		{
			name: "valid url with tag reference",
			url:  "oci://ghcr.io/stefanprodan/charts",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.6",
			},
			want: "ghcr.io/stefanprodan/charts:6.1.6",
		},
		{
			name: "valid url with digest reference",
			url:  "oci://ghcr.io/stefanprodan/charts",
			reference: &sourcev1.OCIRepositoryRef{
				Digest: imgs["6.1.6"].digest.String(),
			},
			want: "ghcr.io/stefanprodan/charts@" + imgs["6.1.6"].digest.String(),
		},
		{
			name: "valid url with semver reference",
			url:  fmt.Sprintf("oci://%s/podinfo", server.registryHost),
			reference: &sourcev1.OCIRepositoryRef{
				SemVer: ">= 6.1.6",
			},
			want: server.registryHost + "/podinfo:6.1.6",
		},
		{
			name:    "invalid url without oci prefix",
			url:     "ghcr.io/stefanprodan/charts",
			wantErr: true,
		},
		{
			name: "valid url with semver filter",
			url:  fmt.Sprintf("oci://%s/podinfo", server.registryHost),
			reference: &sourcev1.OCIRepositoryRef{
				SemVer:       ">= 6.1.x-0",
				SemverFilter: ".*-rc.*",
			},
			want: server.registryHost + "/podinfo:6.1.6-rc.1",
		},
		{
			name: "valid url with semver filter and unexisting version",
			url:  fmt.Sprintf("oci://%s/podinfo", server.registryHost),
			reference: &sourcev1.OCIRepositoryRef{
				SemVer:       ">= 6.1.x-0",
				SemverFilter: ".*-alpha.*",
			},
			wantErr: true,
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&sourcev1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "artifact-url-",
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL:      tt.url,
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
					Insecure: true,
				},
			}

			if tt.reference != nil {
				obj.Spec.Reference = tt.reference
			}

			opts := makeRemoteOptions(ctx, makeTransport(true), authn.DefaultKeychain, nil)
			got, err := r.getArtifactRef(obj, opts)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got.String()).To(Equal(tt.want))
		})
	}
}

func TestOCIRepository_invalidURL(t *testing.T) {
	g := NewWithT(t)

	ns, err := testEnv.CreateNamespace(ctx, "ocirepository-invalid-url-test")
	g.Expect(err).ToNot(HaveOccurred())
	defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

	obj := &sourcev1.OCIRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "ocirepository-reconcile",
			Namespace:    ns.Name,
		},
		Spec: sourcev1.OCIRepositorySpec{
			URL:      "oci://ghcr.io/test/test:v1",
			Interval: metav1.Duration{Duration: 60 * time.Minute},
		},
	}

	g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

	key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}
	resultobj := sourcev1.OCIRepository{}

	// Wait for the object to fail
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, &resultobj); err != nil {
			return false
		}
		readyCondition := conditions.Get(&resultobj, meta.ReadyCondition)
		if readyCondition == nil {
			return false
		}
		return obj.Generation == readyCondition.ObservedGeneration &&
			!conditions.IsUnknown(&resultobj, meta.ReadyCondition)
	}, timeout).Should(BeTrue())

	// Verify that stalled condition is present in status
	stalledCondition := conditions.Get(&resultobj, meta.StalledCondition)
	g.Expect(stalledCondition).ToNot(BeNil())
	g.Expect(stalledCondition.Reason).Should(Equal(sourcev1.URLInvalidReason))
}

func TestOCIRepository_objectLevelWorkloadIdentityFeatureGate(t *testing.T) {
	g := NewWithT(t)

	ns, err := testEnv.CreateNamespace(ctx, "ocirepository-olwifg-test")
	g.Expect(err).ToNot(HaveOccurred())
	defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

	err = testEnv.Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns.Name,
			Name:      "test",
		},
	})
	g.Expect(err).NotTo(HaveOccurred())

	obj := &sourcev1.OCIRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "ocirepository-reconcile",
			Namespace:    ns.Name,
		},
		Spec: sourcev1.OCIRepositorySpec{
			URL:                "oci://ghcr.io/stefanprodan/manifests/podinfo",
			Interval:           metav1.Duration{Duration: 60 * time.Minute},
			Provider:           "aws",
			ServiceAccountName: "test",
		},
	}

	g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

	key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}
	resultobj := &sourcev1.OCIRepository{}

	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, resultobj); err != nil {
			return false
		}
		return conditions.IsStalled(resultobj)
	}).Should(BeTrue())

	stalledCondition := conditions.Get(resultobj, meta.StalledCondition)
	g.Expect(stalledCondition).ToNot(BeNil())
	g.Expect(stalledCondition.Reason).Should(Equal(meta.FeatureGateDisabledReason))
	g.Expect(stalledCondition.Message).Should(Equal("to use spec.serviceAccountName for provider authentication please enable the ObjectLevelWorkloadIdentity feature gate in the controller"))

	auth.EnableObjectLevelWorkloadIdentity()
	t.Cleanup(auth.DisableObjectLevelWorkloadIdentity)

	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, resultobj); err != nil {
			return false
		}
		resultobj.Annotations = map[string]string{
			meta.ReconcileRequestAnnotation: time.Now().Format(time.RFC3339),
		}
		return testEnv.Update(ctx, resultobj) == nil
	}).Should(BeTrue())

	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, resultobj); err != nil {
			return false
		}
		logOCIRepoStatus(t, resultobj)
		return !conditions.IsReady(resultobj) &&
			conditions.GetReason(resultobj, meta.ReadyCondition) == sourcev1.AuthenticationFailedReason
	}).Should(BeTrue())
}

func TestOCIRepository_reconcileStorage(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.OCIRepository, storage *storage.Storage) error
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
		assertArtifact   *meta.Artifact
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *sourcev1.OCIRepository, storage *storage.Storage) error {
				revisions := []string{"a", "b", "c", "d"}

				for n := range revisions {
					v := revisions[n]
					obj.Status.Artifact = &meta.Artifact{
						Path:     fmt.Sprintf("/oci-reconcile-storage/%s.txt", v),
						Revision: v,
					}
					if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
						return err
					}

					if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(v), 0o640); err != nil {
						return err
					}

					if n != len(revisions)-1 {
						time.Sleep(time.Second)
					}
				}

				storage.SetArtifactURL(obj.Status.Artifact)
				conditions.MarkTrue(obj, meta.ReadyCondition, "foo", "bar")
				return nil
			},
			assertArtifact: &meta.Artifact{
				Path:     "/oci-reconcile-storage/d.txt",
				Revision: "d",
				Digest:   "sha256:18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
				URL:      testStorage.Hostname + "/oci-reconcile-storage/d.txt",
				Size:     int64p(int64(len("d"))),
			},
			assertPaths: []string{
				"/oci-reconcile-storage/d.txt",
				"/oci-reconcile-storage/c.txt",
				"!/oci-reconcile-storage/b.txt",
				"!/oci-reconcile-storage/a.txt",
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
		{
			name: "build artifact first time",
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact"),
			},
		},
		{
			name: "notices missing artifact in storage",
			beforeFunc: func(obj *sourcev1.OCIRepository, storage *storage.Storage) error {
				obj.Status.Artifact = &meta.Artifact{
					Path:     "/oci-reconcile-storage/invalid.txt",
					Revision: "e",
				}
				storage.SetArtifactURL(obj.Status.Artifact)
				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"!/oci-reconcile-storage/invalid.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
			},
		},
		{
			name: "notices empty artifact digest",
			beforeFunc: func(obj *sourcev1.OCIRepository, storage *storage.Storage) error {
				f := "empty-digest.txt"

				obj.Status.Artifact = &meta.Artifact{
					Path:     fmt.Sprintf("/oci-reconcile-storage/%s.txt", f),
					Revision: "fake",
				}

				if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
					return err
				}
				if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(f), 0o600); err != nil {
					return err
				}

				// Overwrite with a different digest
				obj.Status.Artifact.Digest = ""

				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"!/oci-reconcile-storage/empty-digest.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
			},
		},
		{
			name: "notices artifact digest mismatch",
			beforeFunc: func(obj *sourcev1.OCIRepository, storage *storage.Storage) error {
				f := "digest-mismatch.txt"

				obj.Status.Artifact = &meta.Artifact{
					Path:     fmt.Sprintf("/oci-reconcile-storage/%s.txt", f),
					Revision: "fake",
				}

				if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
					return err
				}
				if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(f), 0o600); err != nil {
					return err
				}

				// Overwrite with a different digest
				obj.Status.Artifact.Digest = "sha256:6c329d5322473f904e2f908a51c12efa0ca8aa4201dd84f2c9d203a6ab3e9023"

				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"!/oci-reconcile-storage/digest-mismatch.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: disappeared from storage"),
			},
		},
		{
			name: "updates hostname on diff from current",
			beforeFunc: func(obj *sourcev1.OCIRepository, storage *storage.Storage) error {
				obj.Status.Artifact = &meta.Artifact{
					Path:     "/oci-reconcile-storage/hostname.txt",
					Revision: "f",
					Digest:   "sha256:3b9c358f36f0a31b6ad3e14f309c7cf198ac9246e8316f9ce543d5b19ac02b80",
					URL:      "http://outdated.com/oci-reconcile-storage/hostname.txt",
				}
				if err := storage.MkdirAll(*obj.Status.Artifact); err != nil {
					return err
				}
				if err := storage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader("file"), 0o640); err != nil {
					return err
				}
				conditions.MarkTrue(obj, meta.ReadyCondition, "foo", "bar")
				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"/oci-reconcile-storage/hostname.txt",
			},
			assertArtifact: &meta.Artifact{
				Path:     "/oci-reconcile-storage/hostname.txt",
				Revision: "f",
				Digest:   "sha256:3b9c358f36f0a31b6ad3e14f309c7cf198ac9246e8316f9ce543d5b19ac02b80",
				URL:      testStorage.Hostname + "/oci-reconcile-storage/hostname.txt",
				Size:     int64p(int64(len("file"))),
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, "foo", "bar"),
			},
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&sourcev1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Generation:   1,
				},
			}

			if tt.beforeFunc != nil {
				g.Expect(tt.beforeFunc(obj, testStorage)).To(Succeed())
			}

			g.Expect(r.Client.Create(ctx, obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(ctx, obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)

			got, err := r.reconcileStorage(ctx, sp, obj, &meta.Artifact{}, "")
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}

			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Artifact).To(MatchArtifact(tt.assertArtifact))
			if tt.assertArtifact != nil && tt.assertArtifact.URL != "" {
				g.Expect(obj.Status.Artifact.URL).To(Equal(tt.assertArtifact.URL))
			}

			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			for _, p := range tt.assertPaths {
				absoluteP := filepath.Join(testStorage.BasePath, p)
				if !strings.HasPrefix(p, "!") {
					g.Expect(absoluteP).To(BeAnExistingFile())
					continue
				}

				g.Expect(absoluteP).ToNot(BeAnExistingFile())
			}

			// In-progress status condition validity.
			checker := conditionscheck.NewInProgressChecker(r.Client)
			checker.WithT(g).CheckErr(ctx, obj)
		})
	}
}

func TestOCIRepository_ReconcileDelete(t *testing.T) {
	g := NewWithT(t)

	r := &OCIRepositoryReconciler{
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	obj := &sourcev1.OCIRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "reconcile-delete-",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
			Finalizers: []string{
				sourcev1.SourceFinalizer,
			},
		},
		Status: sourcev1.OCIRepositoryStatus{},
	}

	artifact := testStorage.NewArtifactFor(sourcev1.OCIRepositoryKind, obj.GetObjectMeta(), "revision", "foo.txt")
	obj.Status.Artifact = &artifact

	got, err := r.reconcileDelete(ctx, obj)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got).To(Equal(sreconcile.ResultEmpty))
	g.Expect(controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer)).To(BeFalse())
	g.Expect(obj.Status.Artifact).To(BeNil())
}

func TestOCIRepositoryReconciler_notify(t *testing.T) {

	noopErr := serror.NewGeneric(fmt.Errorf("some no-op error"), "NoOpReason")
	noopErr.Ignore = true

	tests := []struct {
		name             string
		res              sreconcile.Result
		resErr           error
		oldObjBeforeFunc func(obj *sourcev1.OCIRepository)
		newObjBeforeFunc func(obj *sourcev1.OCIRepository)
		commit           git.Commit
		wantEvent        string
	}{
		{
			name:   "error - no event",
			res:    sreconcile.ResultEmpty,
			resErr: errors.New("some error"),
		},
		{
			name:   "new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			newObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.URL = "oci://newurl.io"
				obj.Status.Artifact = &meta.Artifact{
					Revision: "xxx",
					Digest:   "yyy",
					Metadata: map[string]string{
						oci.SourceAnnotation:   "https://github.com/stefanprodan/podinfo",
						oci.RevisionAnnotation: "6.1.8/b3b00fe35424a45d373bf4c7214178bc36fd7872",
					},
				}
			},
			wantEvent: "Normal NewArtifact stored artifact with revision 'xxx' from 'oci://newurl.io', origin source 'https://github.com/stefanprodan/podinfo', origin revision '6.1.8/b3b00fe35424a45d373bf4c7214178bc36fd7872'",
		},
		{
			name:   "recovery from failure",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.ReadOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.URL = "oci://newurl.io"
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal Succeeded stored artifact with revision 'xxx' from 'oci://newurl.io'",
		},
		{
			name:   "recovery and new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.ReadOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.URL = "oci://newurl.io"
				obj.Status.Artifact = &meta.Artifact{Revision: "aaa", Digest: "bbb"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal NewArtifact stored artifact with revision 'aaa' from 'oci://newurl.io'",
		},
		{
			name:   "no updates",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
		},
		{
			name:   "no updates on requeue",
			res:    sreconcile.ResultRequeue,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &meta.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.URLInvalidReason, "ready")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			recorder := record.NewFakeRecorder(32)

			oldObj := &sourcev1.OCIRepository{}
			newObj := oldObj.DeepCopy()

			if tt.oldObjBeforeFunc != nil {
				tt.oldObjBeforeFunc(oldObj)
			}
			if tt.newObjBeforeFunc != nil {
				tt.newObjBeforeFunc(newObj)
			}

			reconciler := &OCIRepositoryReconciler{
				EventRecorder: recorder,
				patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
			}
			reconciler.notify(ctx, oldObj, newObj, tt.res, tt.resErr)

			select {
			case x, ok := <-recorder.Events:
				g.Expect(ok).To(Equal(tt.wantEvent != ""), "unexpected event received")
				if tt.wantEvent != "" {
					g.Expect(x).To(ContainSubstring(tt.wantEvent))
				}
			default:
				if tt.wantEvent != "" {
					t.Errorf("expected some event to be emitted")
				}
			}
		})
	}
}

type artifactFixture struct {
	expectedPath     string
	expectedChecksum string
}

type podinfoImage struct {
	url    string
	tag    string
	digest gcrv1.Hash
}

func createPodinfoImageFromTar(tarFileName, tag, registryURL string, opts ...crane.Option) (*podinfoImage, error) {
	// Create Image
	image, err := crane.Load(path.Join("testdata", "podinfo", tarFileName))
	if err != nil {
		return nil, err
	}

	image = setPodinfoImageAnnotations(image, tag)

	// url.Parse doesn't handle urls with no scheme well e.g localhost:<port>
	if !(strings.HasPrefix(registryURL, "http://") || strings.HasPrefix(registryURL, "https://")) {
		registryURL = fmt.Sprintf("http://%s", registryURL)
	}

	myURL, err := url.Parse(registryURL)
	if err != nil {
		return nil, err
	}
	repositoryURL := fmt.Sprintf("%s/podinfo", myURL.Host)

	// Image digest
	podinfoImageDigest, err := image.Digest()
	if err != nil {
		return nil, err
	}

	// Push image
	err = crane.Push(image, repositoryURL, opts...)
	if err != nil {
		return nil, err
	}

	// Tag the image
	err = crane.Tag(repositoryURL, tag, opts...)
	if err != nil {
		return nil, err
	}

	return &podinfoImage{
		url:    "oci://" + repositoryURL,
		tag:    tag,
		digest: podinfoImageDigest,
	}, nil
}

func pushMultiplePodinfoImages(serverURL string, insecure bool, versions ...string) (map[string]podinfoImage, error) {
	podinfoVersions := make(map[string]podinfoImage)

	var opts []crane.Option
	// If the registry is insecure then instruct configure an insecure HTTP client,
	// otherwise add the root CA certificate since the HTTPS server is self signed.
	if insecure {
		opts = append(opts, crane.Insecure)
	} else {
		transport := http.DefaultTransport.(*http.Transport)
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(tlsCA)
		transport.TLSClientConfig = &tls.Config{
			RootCAs: pool,
		}
		opts = append(opts, crane.WithTransport(transport))
	}
	for i := 0; i < len(versions); i++ {
		pi, err := createPodinfoImageFromTar(fmt.Sprintf("podinfo-%s.tar", versions[i]), versions[i], serverURL, opts...)
		if err != nil {
			return nil, err
		}

		podinfoVersions[versions[i]] = *pi

	}

	return podinfoVersions, nil
}

func setPodinfoImageAnnotations(img gcrv1.Image, tag string) gcrv1.Image {
	metadata := map[string]string{
		oci.SourceAnnotation:   "https://github.com/stefanprodan/podinfo",
		oci.RevisionAnnotation: fmt.Sprintf("%s@sha1:b3b00fe35424a45d373bf4c7214178bc36fd7872", tag),
	}
	return mutate.Annotations(img, metadata).(gcrv1.Image)
}

func TestOCIContentConfigChanged(t *testing.T) {
	tests := []struct {
		name   string
		spec   sourcev1.OCIRepositorySpec
		status sourcev1.OCIRepositoryStatus
		want   bool
	}{
		{
			name: "same ignore, no layer selector",
			spec: sourcev1.OCIRepositorySpec{
				Ignore: ptr.To("nnn"),
			},
			status: sourcev1.OCIRepositoryStatus{
				ObservedIgnore: ptr.To("nnn"),
			},
			want: false,
		},
		{
			name: "different ignore, no layer selector",
			spec: sourcev1.OCIRepositorySpec{
				Ignore: ptr.To("nnn"),
			},
			status: sourcev1.OCIRepositoryStatus{
				ObservedIgnore: ptr.To("mmm"),
			},
			want: true,
		},
		{
			name: "same ignore, same layer selector",
			spec: sourcev1.OCIRepositorySpec{
				Ignore: ptr.To("nnn"),
				LayerSelector: &sourcev1.OCILayerSelector{
					MediaType: "foo",
					Operation: sourcev1.OCILayerExtract,
				},
			},
			status: sourcev1.OCIRepositoryStatus{
				ObservedIgnore: ptr.To("nnn"),
				ObservedLayerSelector: &sourcev1.OCILayerSelector{
					MediaType: "foo",
					Operation: sourcev1.OCILayerExtract,
				},
			},
			want: false,
		},
		{
			name: "same ignore, different layer selector operation",
			spec: sourcev1.OCIRepositorySpec{
				Ignore: ptr.To("nnn"),
				LayerSelector: &sourcev1.OCILayerSelector{
					MediaType: "foo",
					Operation: sourcev1.OCILayerCopy,
				},
			},
			status: sourcev1.OCIRepositoryStatus{
				ObservedIgnore: ptr.To("nnn"),
				ObservedLayerSelector: &sourcev1.OCILayerSelector{
					MediaType: "foo",
					Operation: sourcev1.OCILayerExtract,
				},
			},
			want: true,
		},
		{
			name: "same ignore, different layer selector mediatype",
			spec: sourcev1.OCIRepositorySpec{
				Ignore: ptr.To("nnn"),
				LayerSelector: &sourcev1.OCILayerSelector{
					MediaType: "bar",
					Operation: sourcev1.OCILayerExtract,
				},
			},
			status: sourcev1.OCIRepositoryStatus{
				ObservedIgnore: ptr.To("nnn"),
				ObservedLayerSelector: &sourcev1.OCILayerSelector{
					MediaType: "foo",
					Operation: sourcev1.OCILayerExtract,
				},
			},
			want: true,
		},
		{
			name: "no ignore, same layer selector",
			spec: sourcev1.OCIRepositorySpec{
				LayerSelector: &sourcev1.OCILayerSelector{
					MediaType: "foo",
					Operation: sourcev1.OCILayerExtract,
				},
			},
			status: sourcev1.OCIRepositoryStatus{
				ObservedLayerSelector: &sourcev1.OCILayerSelector{
					MediaType: "foo",
					Operation: sourcev1.OCILayerExtract,
				},
			},
			want: false,
		},
		{
			name: "no ignore, different layer selector",
			spec: sourcev1.OCIRepositorySpec{
				LayerSelector: &sourcev1.OCILayerSelector{
					MediaType: "bar",
					Operation: sourcev1.OCILayerExtract,
				},
			},
			status: sourcev1.OCIRepositoryStatus{
				ObservedLayerSelector: &sourcev1.OCILayerSelector{
					MediaType: "foo",
					Operation: sourcev1.OCILayerExtract,
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.OCIRepository{
				Spec:   tt.spec,
				Status: tt.status,
			}

			g.Expect(ociContentConfigChanged(obj)).To(Equal(tt.want))
		})
	}
}
