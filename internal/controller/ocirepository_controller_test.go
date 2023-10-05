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
	. "github.com/onsi/gomega"
	coptions "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/oci"
	"github.com/fluxcd/pkg/runtime/conditions"
	conditionscheck "github.com/fluxcd/pkg/runtime/conditions/check"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/tar"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	ociv1 "github.com/fluxcd/source-controller/api/v1beta2"
	intdigest "github.com/fluxcd/source-controller/internal/digest"
	serror "github.com/fluxcd/source-controller/internal/error"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
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

	ocirepo := &ociv1.OCIRepository{}
	ocirepo.Name = "test-ocirepo"
	ocirepo.Namespace = namespaceName
	ocirepo.Spec = ociv1.OCIRepositorySpec{
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
			operation: ociv1.OCILayerCopy,
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

			origObj := &ociv1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "ocirepository-reconcile",
					Namespace:    ns.Name,
				},
				Spec: ociv1.OCIRepositorySpec{
					URL:       tt.url,
					Interval:  metav1.Duration{Duration: 60 * time.Minute},
					Reference: &ociv1.OCIRepositoryRef{},
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
				obj.Spec.LayerSelector = &ociv1.OCILayerSelector{MediaType: tt.mediaType}

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

			obj := &ociv1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "ocirepository-reconcile",
					Namespace:    ns.Name,
				},
				Spec: ociv1.OCIRepositorySpec{
					URL:      tt.url,
					Interval: metav1.Duration{Duration: 60 * time.Minute},
					Reference: &ociv1.OCIRepositoryRef{
						Tag: tt.tag,
					},
					LayerSelector: &ociv1.OCILayerSelector{
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, ociv1.OCIPullFailedReason, "failed to determine artifact digest"),
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, ociv1.OCIPullFailedReason, "UNAUTHORIZED"),
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, ociv1.OCIPullFailedReason, "UNAUTHORIZED"),
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
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
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
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, ociv1.OCIPullFailedReason, "failed to determine artifact digest"),
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, ociv1.AuthenticationFailedReason, "cannot append certificate into certificate pool: invalid CA certificate"),
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
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get credential from"),
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
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithStatusSubresource(&ociv1.OCIRepository{})

			obj := &ociv1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-strategy-",
					Generation:   1,
				},
				Spec: ociv1.OCIRepositorySpec{
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
			obj.Spec.Reference = &ociv1.OCIRepositoryRef{
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
			got, err := r.reconcileSource(ctx, sp, obj, &sourcev1.Artifact{}, tmpDir)
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
			oci.CACert:     tlsCA,
			oci.ClientCert: clientPublicKey,
			oci.ClientKey:  clientPrivateKey,
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
					oci.CACert:     tlsCA,
					oci.ClientCert: clientPublicKey,
					oci.ClientKey:  []byte("invalid-key"),
				},
			},
			expectreadyconition:   false,
			expectedstatusmessage: "failed to generate transport for '<url>': tls: failed to find any PEM data in key input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ns, err := testEnv.CreateNamespace(ctx, "ocirepository-test")
			g.Expect(err).ToNot(HaveOccurred())
			defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

			obj := &ociv1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "ocirepository-test-resource",
					Namespace:    ns.Name,
					Generation:   1,
				},
				Spec: ociv1.OCIRepositorySpec{
					URL:       tt.url,
					Interval:  metav1.Duration{Duration: 60 * time.Minute},
					Reference: &ociv1.OCIRepositoryRef{Digest: tt.digest.String()},
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

			resultobj := ociv1.OCIRepository{}

			// Wait for the finalizer to be set
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, &resultobj); err != nil {
					return false
				}
				return len(resultobj.Finalizers) > 0
			}, timeout).Should(BeTrue())

			// Wait for the object to fail
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
		reference        *ociv1.OCIRepositoryRef
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
			reference: &ociv1.OCIRepositoryRef{
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
			reference: &ociv1.OCIRepositoryRef{
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
			reference: &ociv1.OCIRepositoryRef{
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
			reference: &ociv1.OCIRepositoryRef{
				Tag: "6.1.0",
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, ociv1.OCIPullFailedReason, " MANIFEST_UNKNOWN"),
			},
		},
		{
			name: "invalid semver reference",
			reference: &ociv1.OCIRepositoryRef{
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
			reference: &ociv1.OCIRepositoryRef{
				Digest: "invalid",
			},
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, ociv1.OCIPullFailedReason, "failed to determine artifact digest"),
			},
		},
		{
			name: "semver should take precedence over tag",
			reference: &ociv1.OCIRepositoryRef{
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
			reference: &ociv1.OCIRepositoryRef{
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
		WithStatusSubresource(&ociv1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &ociv1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "checkout-strategy-",
					Generation:   1,
				},
				Spec: ociv1.OCIRepositorySpec{
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

			artifact := &sourcev1.Artifact{}
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

func TestOCIRepository_reconcileSource_verifyOCISourceSignature(t *testing.T) {
	g := NewWithT(t)

	tests := []struct {
		name             string
		reference        *ociv1.OCIRepositoryRef
		insecure         bool
		want             sreconcile.Result
		wantErr          bool
		wantErrMsg       string
		shouldSign       bool
		keyless          bool
		beforeFunc       func(obj *ociv1.OCIRepository, tag, revision string)
		assertConditions []metav1.Condition
	}{
		{
			name: "signed image should pass verification",
			reference: &ociv1.OCIRepositoryRef{
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
			reference: &ociv1.OCIRepositoryRef{
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
			reference: &ociv1.OCIRepositoryRef{
				Tag: "6.1.5",
			},
			wantErr: true,
			want:    sreconcile.ResultEmpty,
			keyless: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider '<provider> keyless': no matching signatures"),
			},
		},
		{
			name:      "verify failed before, removed from spec, remove condition",
			reference: &ociv1.OCIRepositoryRef{Tag: "6.1.4"},
			beforeFunc: func(obj *ociv1.OCIRepository, tag, revision string) {
				conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, "VerifyFailed", "fail msg")
				obj.Spec.Verify = nil
				obj.Status.Artifact = &sourcev1.Artifact{Revision: fmt.Sprintf("%s@%s", tag, revision)}
			},
			want: sreconcile.ResultSuccess,
		},
		{
			name:       "same artifact, verified before, change in obj gen verify again",
			reference:  &ociv1.OCIRepositoryRef{Tag: "6.1.4"},
			shouldSign: true,
			beforeFunc: func(obj *ociv1.OCIRepository, tag, revision string) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: fmt.Sprintf("%s@%s", tag, revision)}
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
			reference:  &ociv1.OCIRepositoryRef{Tag: "6.1.4"},
			shouldSign: true,
			beforeFunc: func(obj *ociv1.OCIRepository, tag, revision string) {
				// Artifact present and custom verified condition reason/message.
				obj.Status.Artifact = &sourcev1.Artifact{Revision: fmt.Sprintf("%s@%s", tag, revision)}
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Verified", "verified")
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, "Verified", "verified"),
			},
		},
		{
			name: "signed image on an insecure registry passes verification",
			reference: &ociv1.OCIRepositoryRef{
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
		WithStatusSubresource(&ociv1.OCIRepository{})

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

			obj := &ociv1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "verify-oci-source-signature-",
					Generation:   1,
				},
				Spec: ociv1.OCIRepositorySpec{
					URL: fmt.Sprintf("oci://%s/podinfo", server.registryHost),
					Verify: &ociv1.OCIRepositoryVerification{
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

			artifact := &sourcev1.Artifact{}
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
		reference        *ociv1.OCIRepositoryRef
		want             sreconcile.Result
		wantErr          bool
		wantErrMsg       string
		beforeFunc       func(obj *ociv1.OCIRepository)
		assertConditions []metav1.Condition
		revision         string
	}{
		{
			name: "signed image with no identity matching specified should pass verification",
			reference: &ociv1.OCIRepositoryRef{
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
			reference: &ociv1.OCIRepositoryRef{
				Tag: "6.5.1",
			},
			want: sreconcile.ResultSuccess,
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.Verify.MatchOIDCIdentity = []ociv1.OIDCIdentityMatch{
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
			reference: &ociv1.OCIRepositoryRef{
				Tag: "6.5.1",
			},
			want: sreconcile.ResultSuccess,
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.Verify.MatchOIDCIdentity = []ociv1.OIDCIdentityMatch{
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
			reference: &ociv1.OCIRepositoryRef{
				Tag: "6.5.1",
			},
			wantErr: true,
			want:    sreconcile.ResultEmpty,
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.Verify.MatchOIDCIdentity = []ociv1.OIDCIdentityMatch{
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
			reference: &ociv1.OCIRepositoryRef{
				Tag: "6.1.0",
			},
			wantErr: true,
			want:    sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.UnknownCondition(meta.ReadyCondition, meta.ProgressingReason, "building artifact: new revision '<revision>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider '<provider> keyless': no matching signatures"),
			},
			revision: "6.1.0@sha256:3816fe9636a297f0c934b1fa0f46fe4c068920375536ac2803604adfb4c55894",
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&ociv1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &ociv1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "verify-oci-source-signature-",
					Generation:   1,
				},
				Spec: ociv1.OCIRepositorySpec{
					URL: "oci://ghcr.io/stefanprodan/manifests/podinfo",
					Verify: &ociv1.OCIRepositoryVerification{
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

			artifact := &sourcev1.Artifact{}
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
		beforeFunc func(obj *ociv1.OCIRepository)
		afterFunc  func(g *WithT, artifact *sourcev1.Artifact)
	}{
		{
			name: "full reconcile - no existing artifact",
			afterFunc: func(g *WithT, artifact *sourcev1.Artifact) {
				g.Expect(artifact.Metadata).ToNot(BeEmpty())
			},
		},
		{
			name: "noop - artifact revisions match",
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *sourcev1.Artifact) {
				g.Expect(artifact.Metadata).To(BeEmpty())
			},
		},
		{
			name: "full reconcile - same rev, unobserved ignore",
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Status.ObservedIgnore = ptr.To("aaa")
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *sourcev1.Artifact) {
				g.Expect(artifact.Metadata).ToNot(BeEmpty())
			},
		},
		{
			name: "noop - same rev, observed ignore",
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.Ignore = ptr.To("aaa")
				obj.Status.ObservedIgnore = ptr.To("aaa")
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *sourcev1.Artifact) {
				g.Expect(artifact.Metadata).To(BeEmpty())
			},
		},
		{
			name: "full reconcile - same rev, unobserved layer selector",
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.LayerSelector = &ociv1.OCILayerSelector{
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Operation: ociv1.OCILayerCopy,
				}
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *sourcev1.Artifact) {
				g.Expect(artifact.Metadata).ToNot(BeEmpty())
			},
		},
		{
			name: "noop - same rev, observed layer selector",
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.LayerSelector = &ociv1.OCILayerSelector{
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Operation: ociv1.OCILayerCopy,
				}
				obj.Status.ObservedLayerSelector = &ociv1.OCILayerSelector{
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Operation: ociv1.OCILayerCopy,
				}
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *sourcev1.Artifact) {
				g.Expect(artifact.Metadata).To(BeEmpty())
			},
		},
		{
			name: "full reconcile - same rev, observed layer selector changed",
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.LayerSelector = &ociv1.OCILayerSelector{
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Operation: ociv1.OCILayerExtract,
				}
				obj.Status.ObservedLayerSelector = &ociv1.OCILayerSelector{
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Operation: ociv1.OCILayerCopy,
				}
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: testRevision,
				}
			},
			afterFunc: func(g *WithT, artifact *sourcev1.Artifact) {
				g.Expect(artifact.Metadata).ToNot(BeEmpty())
			},
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&ociv1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &ociv1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "noop-",
					Generation:   1,
				},
				Spec: ociv1.OCIRepositorySpec{
					URL:       fmt.Sprintf("oci://%s/podinfo", server.registryHost),
					Reference: &ociv1.OCIRepositoryRef{Tag: "6.1.5"},
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

			artifact := &sourcev1.Artifact{}
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
		artifact         *sourcev1.Artifact
		beforeFunc       func(obj *ociv1.OCIRepository)
		want             sreconcile.Result
		wantErr          bool
		assertArtifact   *sourcev1.Artifact
		assertPaths      []string
		assertConditions []metav1.Condition
		afterFunc        func(g *WithT, obj *ociv1.OCIRepository)
	}{
		{
			name:       "Archiving Artifact creates correct files and condition",
			targetPath: "testdata/oci/repository",
			artifact: &sourcev1.Artifact{
				Revision: "revision",
			},
			beforeFunc: func(obj *ociv1.OCIRepository) {
				conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision")
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *ociv1.OCIRepository) {
				g.Expect(obj.Status.Artifact.Digest).To(Equal("sha256:de37cb640bfe6c789f2b131416d259747d5757f7fe5e1d9d48f32d8c30af5934"))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "Artifact with source ignore",
			targetPath: "testdata/oci/repository",
			artifact:   &sourcev1.Artifact{Revision: "revision"},
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.Ignore = ptr.To("foo.txt")
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *ociv1.OCIRepository) {
				g.Expect(obj.Status.Artifact.Digest).To(Equal("sha256:05aada03e3e3e96f5f85a8f31548d833974ce862be14942fb3313eef2df861ec"))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name: "No status changes if artifact is already present",
			artifact: &sourcev1.Artifact{
				Revision: "revision",
			},
			targetPath: "testdata/oci/repository",
			want:       sreconcile.ResultSuccess,
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: "revision",
				}
			},
			assertArtifact: &sourcev1.Artifact{
				Revision: "revision",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "Artifact already present, unobserved ignore, rebuild artifact",
			targetPath: "testdata/oci/repository",
			artifact: &sourcev1.Artifact{
				Revision: "revision",
			},
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "revision"}
				obj.Spec.Ignore = ptr.To("aaa")
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *ociv1.OCIRepository) {
				g.Expect(*obj.Status.ObservedIgnore).To(Equal("aaa"))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "Artifact already present, unobserved layer selector, rebuild artifact",
			targetPath: "testdata/oci/repository",
			artifact: &sourcev1.Artifact{
				Revision: "revision",
			},
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.LayerSelector = &ociv1.OCILayerSelector{MediaType: "foo"}
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "revision"}
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *ociv1.OCIRepository) {
				g.Expect(obj.Status.ObservedLayerSelector.MediaType).To(Equal("foo"))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "Artifact already present, observed layer selector changed, rebuild artifact",
			targetPath: "testdata/oci/repository",
			artifact: &sourcev1.Artifact{
				Revision: "revision",
				Path:     "foo.txt",
			},
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.LayerSelector = &ociv1.OCILayerSelector{
					MediaType: "foo",
					Operation: ociv1.OCILayerCopy,
				}
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "revision"}
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *ociv1.OCIRepository) {
				g.Expect(obj.Status.ObservedLayerSelector.MediaType).To(Equal("foo"))
				g.Expect(obj.Status.ObservedLayerSelector.Operation).To(Equal(ociv1.OCILayerCopy))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "Artifact already present, observed ignore and layer selector, up-to-date",
			targetPath: "testdata/oci/repository",
			artifact: &sourcev1.Artifact{
				Revision: "revision",
			},
			beforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.Ignore = ptr.To("aaa")
				obj.Spec.LayerSelector = &ociv1.OCILayerSelector{MediaType: "foo"}
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "revision"}
				obj.Status.ObservedIgnore = ptr.To("aaa")
				obj.Status.ObservedLayerSelector = &ociv1.OCILayerSelector{MediaType: "foo"}
			},
			want: sreconcile.ResultSuccess,
			assertArtifact: &sourcev1.Artifact{
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
		WithStatusSubresource(&ociv1.OCIRepository{})

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

			obj := &ociv1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "reconcile-artifact-",
					Generation:   1,
				},
			}
			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			artifact := &sourcev1.Artifact{}
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

			for _, path := range tt.assertPaths {
				localPath := testStorage.LocalPath(*obj.GetArtifact())
				path = filepath.Join(filepath.Dir(localPath), path)
				_, err := os.Lstat(path)
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

	imgs, err := pushMultiplePodinfoImages(server.registryHost, true, "6.1.4", "6.1.5", "6.1.6")
	g.Expect(err).ToNot(HaveOccurred())

	tests := []struct {
		name      string
		url       string
		reference *ociv1.OCIRepositoryRef
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
			reference: &ociv1.OCIRepositoryRef{
				Tag: "6.1.6",
			},
			want: "ghcr.io/stefanprodan/charts:6.1.6",
		},
		{
			name: "valid url with digest reference",
			url:  "oci://ghcr.io/stefanprodan/charts",
			reference: &ociv1.OCIRepositoryRef{
				Digest: imgs["6.1.6"].digest.String(),
			},
			want: "ghcr.io/stefanprodan/charts@" + imgs["6.1.6"].digest.String(),
		},
		{
			name: "valid url with semver reference",
			url:  fmt.Sprintf("oci://%s/podinfo", server.registryHost),
			reference: &ociv1.OCIRepositoryRef{
				SemVer: ">= 6.1.6",
			},
			want: server.registryHost + "/podinfo:6.1.6",
		},
		{
			name:    "invalid url without oci prefix",
			url:     "ghcr.io/stefanprodan/charts",
			wantErr: true,
		},
	}

	clientBuilder := fakeclient.NewClientBuilder().
		WithScheme(testEnv.GetScheme()).
		WithStatusSubresource(&ociv1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &ociv1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "artifact-url-",
				},
				Spec: ociv1.OCIRepositorySpec{
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

func TestOCIRepository_stalled(t *testing.T) {
	g := NewWithT(t)

	ns, err := testEnv.CreateNamespace(ctx, "ocirepository-stalled-test")
	g.Expect(err).ToNot(HaveOccurred())
	defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

	obj := &ociv1.OCIRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "ocirepository-reconcile",
			Namespace:    ns.Name,
		},
		Spec: ociv1.OCIRepositorySpec{
			URL:      "oci://ghcr.io/test/test:v1",
			Interval: metav1.Duration{Duration: 60 * time.Minute},
		},
	}

	g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

	key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}
	resultobj := ociv1.OCIRepository{}

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

func TestOCIRepository_reconcileStorage(t *testing.T) {
	tests := []struct {
		name             string
		beforeFunc       func(obj *ociv1.OCIRepository, storage *Storage) error
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
		assertArtifact   *sourcev1.Artifact
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *ociv1.OCIRepository, storage *Storage) error {
				revisions := []string{"a", "b", "c", "d"}

				for n := range revisions {
					v := revisions[n]
					obj.Status.Artifact = &sourcev1.Artifact{
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
			assertArtifact: &sourcev1.Artifact{
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
			beforeFunc: func(obj *ociv1.OCIRepository, storage *Storage) error {
				obj.Status.Artifact = &sourcev1.Artifact{
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
			beforeFunc: func(obj *ociv1.OCIRepository, storage *Storage) error {
				f := "empty-digest.txt"

				obj.Status.Artifact = &sourcev1.Artifact{
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
			beforeFunc: func(obj *ociv1.OCIRepository, storage *Storage) error {
				f := "digest-mismatch.txt"

				obj.Status.Artifact = &sourcev1.Artifact{
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
			beforeFunc: func(obj *ociv1.OCIRepository, storage *Storage) error {
				obj.Status.Artifact = &sourcev1.Artifact{
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
			assertArtifact: &sourcev1.Artifact{
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
		WithStatusSubresource(&ociv1.OCIRepository{})

	r := &OCIRepositoryReconciler{
		Client:        clientBuilder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
		patchOptions:  getPatchOptions(ociRepositoryReadyCondition.Owned, "sc"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &ociv1.OCIRepository{
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

			got, err := r.reconcileStorage(ctx, sp, obj, &sourcev1.Artifact{}, "")
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

	obj := &ociv1.OCIRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "reconcile-delete-",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
			Finalizers: []string{
				sourcev1.SourceFinalizer,
			},
		},
		Status: ociv1.OCIRepositoryStatus{},
	}

	artifact := testStorage.NewArtifactFor(ociv1.OCIRepositoryKind, obj.GetObjectMeta(), "revision", "foo.txt")
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
		oldObjBeforeFunc func(obj *ociv1.OCIRepository)
		newObjBeforeFunc func(obj *ociv1.OCIRepository)
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
			newObjBeforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.URL = "oci://newurl.io"
				obj.Status.Artifact = &sourcev1.Artifact{
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
			oldObjBeforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.ReadOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.URL = "oci://newurl.io"
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal Succeeded stored artifact with revision 'xxx' from 'oci://newurl.io'",
		},
		{
			name:   "recovery and new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.ReadOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Spec.URL = "oci://newurl.io"
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "aaa", Digest: "bbb"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal NewArtifact stored artifact with revision 'aaa' from 'oci://newurl.io'",
		},
		{
			name:   "no updates",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjBeforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
		},
		{
			name:   "no updates on requeue",
			res:    sreconcile.ResultRequeue,
			resErr: nil,
			oldObjBeforeFunc: func(obj *ociv1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Digest: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.URLInvalidReason, "ready")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			recorder := record.NewFakeRecorder(32)

			oldObj := &ociv1.OCIRepository{}
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
		spec   ociv1.OCIRepositorySpec
		status ociv1.OCIRepositoryStatus
		want   bool
	}{
		{
			name: "same ignore, no layer selector",
			spec: ociv1.OCIRepositorySpec{
				Ignore: ptr.To("nnn"),
			},
			status: ociv1.OCIRepositoryStatus{
				ObservedIgnore: ptr.To("nnn"),
			},
			want: false,
		},
		{
			name: "different ignore, no layer selector",
			spec: ociv1.OCIRepositorySpec{
				Ignore: ptr.To("nnn"),
			},
			status: ociv1.OCIRepositoryStatus{
				ObservedIgnore: ptr.To("mmm"),
			},
			want: true,
		},
		{
			name: "same ignore, same layer selector",
			spec: ociv1.OCIRepositorySpec{
				Ignore: ptr.To("nnn"),
				LayerSelector: &ociv1.OCILayerSelector{
					MediaType: "foo",
					Operation: ociv1.OCILayerExtract,
				},
			},
			status: ociv1.OCIRepositoryStatus{
				ObservedIgnore: ptr.To("nnn"),
				ObservedLayerSelector: &ociv1.OCILayerSelector{
					MediaType: "foo",
					Operation: ociv1.OCILayerExtract,
				},
			},
			want: false,
		},
		{
			name: "same ignore, different layer selector operation",
			spec: ociv1.OCIRepositorySpec{
				Ignore: ptr.To("nnn"),
				LayerSelector: &ociv1.OCILayerSelector{
					MediaType: "foo",
					Operation: ociv1.OCILayerCopy,
				},
			},
			status: ociv1.OCIRepositoryStatus{
				ObservedIgnore: ptr.To("nnn"),
				ObservedLayerSelector: &ociv1.OCILayerSelector{
					MediaType: "foo",
					Operation: ociv1.OCILayerExtract,
				},
			},
			want: true,
		},
		{
			name: "same ignore, different layer selector mediatype",
			spec: ociv1.OCIRepositorySpec{
				Ignore: ptr.To("nnn"),
				LayerSelector: &ociv1.OCILayerSelector{
					MediaType: "bar",
					Operation: ociv1.OCILayerExtract,
				},
			},
			status: ociv1.OCIRepositoryStatus{
				ObservedIgnore: ptr.To("nnn"),
				ObservedLayerSelector: &ociv1.OCILayerSelector{
					MediaType: "foo",
					Operation: ociv1.OCILayerExtract,
				},
			},
			want: true,
		},
		{
			name: "no ignore, same layer selector",
			spec: ociv1.OCIRepositorySpec{
				LayerSelector: &ociv1.OCILayerSelector{
					MediaType: "foo",
					Operation: ociv1.OCILayerExtract,
				},
			},
			status: ociv1.OCIRepositoryStatus{
				ObservedLayerSelector: &ociv1.OCILayerSelector{
					MediaType: "foo",
					Operation: ociv1.OCILayerExtract,
				},
			},
			want: false,
		},
		{
			name: "no ignore, different layer selector",
			spec: ociv1.OCIRepositorySpec{
				LayerSelector: &ociv1.OCILayerSelector{
					MediaType: "bar",
					Operation: ociv1.OCILayerExtract,
				},
			},
			status: ociv1.OCIRepositoryStatus{
				ObservedLayerSelector: &ociv1.OCILayerSelector{
					MediaType: "foo",
					Operation: ociv1.OCILayerExtract,
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &ociv1.OCIRepository{
				Spec:   tt.spec,
				Status: tt.status,
			}

			g.Expect(ociContentConfigChanged(obj)).To(Equal(tt.want))
		})
	}
}
