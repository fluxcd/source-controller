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

package controllers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darkowlzz/controller-check/status"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	. "github.com/onsi/gomega"
	coptions "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/pointer"
	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/oci"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/untar"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
)

const ociRepoEmptyContentConfigChecksum = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestOCIRepository_Reconcile(t *testing.T) {
	g := NewWithT(t)

	// Registry server with public images
	tmpDir := t.TempDir()
	regServer, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	if err != nil {
		g.Expect(err).ToNot(HaveOccurred())
	}

	podinfoVersions, err := pushMultiplePodinfoImages(regServer.registryHost, "6.1.4", "6.1.5", "6.1.6")

	tests := []struct {
		name           string
		url            string
		tag            string
		semver         string
		digest         string
		mediaType      string
		operation      string
		assertArtifact []artifactFixture
	}{
		{
			name:      "public tag",
			url:       podinfoVersions["6.1.6"].url,
			tag:       podinfoVersions["6.1.6"].tag,
			digest:    fmt.Sprintf("%s/%s", podinfoVersions["6.1.6"].tag, podinfoVersions["6.1.6"].digest.Hex),
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
			name:   "public semver",
			url:    podinfoVersions["6.1.5"].url,
			semver: ">= 6.1 <= 6.1.5",
			digest: fmt.Sprintf("%s/%s", podinfoVersions["6.1.5"].tag, podinfoVersions["6.1.5"].digest.Hex),
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

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "ocirepository-reconcile",
					Namespace:    ns.Name,
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL:       tt.url,
					Interval:  metav1.Duration{Duration: 60 * time.Minute},
					Reference: &sourcev1.OCIRepositoryRef{},
				},
			}

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
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, obj); err != nil {
					return false
				}
				if !conditions.IsReady(obj) {
					return false
				}
				readyCondition := conditions.Get(obj, meta.ReadyCondition)
				return obj.Generation == readyCondition.ObservedGeneration &&
					obj.Generation == obj.Status.ObservedGeneration
			}, timeout).Should(BeTrue())

			// Check if the revision matches the expected digest
			g.Expect(obj.Status.Artifact.Revision).To(Equal(tt.digest))

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

			ep, err := untar.Untar(f, tmp)
			g.Expect(err).ToNot(HaveOccurred())
			t.Logf("extracted summary: %s", ep)

			for _, af := range tt.assertArtifact {
				expectedFile := filepath.Join(tmp, af.expectedPath)
				g.Expect(expectedFile).To(BeAnExistingFile())

				f2, err := os.Open(expectedFile)
				g.Expect(err).ToNot(HaveOccurred())
				defer f2.Close()

				h := testStorage.Checksum(f2)
				t.Logf("file %q hash: %q", expectedFile, h)
				g.Expect(h).To(Equal(af.expectedChecksum))
			}

			// Check if the object status is valid
			condns := &status.Conditions{NegativePolarity: ociRepositoryReadyCondition.NegativePolarity}
			checker := status.NewChecker(testEnv.Client, condns)
			checker.CheckErr(ctx, obj)

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
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, obj); err != nil {
					return apierrors.IsNotFound(err)
				}
				return false
			}, timeout).Should(BeTrue())
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

	podinfoVersions, err := pushMultiplePodinfoImages(regServer.registryHost, "6.1.4", "6.1.5", "6.1.6")

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
				return readyCondition != nil
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
		provider         string
		providerImg      string
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "HTTP without basic auth",
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
			},
		},
		{
			name: "HTTP with basic auth secret",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			craneOpts: []crane.Option{crane.WithAuth(&authn.Basic{
				Username: testRegistryUsername,
				Password: testRegistryPassword,
			}),
			},
			secretOpts: secretOptions{
				username:      testRegistryUsername,
				password:      testRegistryPassword,
				includeSecret: true,
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
			},
		},
		{
			name: "HTTP with serviceaccount",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			craneOpts: []crane.Option{crane.WithAuth(&authn.Basic{
				Username: testRegistryUsername,
				Password: testRegistryPassword,
			}),
			},
			secretOpts: secretOptions{
				username:  testRegistryUsername,
				password:  testRegistryPassword,
				includeSA: true,
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
			},
		},
		{
			name: "HTTP registry - basic auth with missing secret",
			want: sreconcile.ResultEmpty,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			wantErr: true,
			craneOpts: []crane.Option{crane.WithAuth(&authn.Basic{
				Username: testRegistryUsername,
				Password: testRegistryPassword,
			}),
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIPullFailedReason, "failed to determine artifact digest"),
			},
		},
		{
			name:    "HTTP registry - basic auth with invalid secret",
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			craneOpts: []crane.Option{crane.WithAuth(&authn.Basic{
				Username: testRegistryUsername,
				Password: testRegistryPassword,
			}),
			},
			secretOpts: secretOptions{
				username:      "wrong-pass",
				password:      "wrong-pass",
				includeSecret: true,
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIPullFailedReason, "UNAUTHORIZED"),
			},
		},
		{
			name:    "HTTP registry - basic auth with invalid serviceaccount",
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			craneOpts: []crane.Option{crane.WithAuth(&authn.Basic{
				Username: testRegistryUsername,
				Password: testRegistryPassword,
			}),
			},
			secretOpts: secretOptions{
				username:  "wrong-pass",
				password:  "wrong-pass",
				includeSA: true,
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIPullFailedReason, "UNAUTHORIZED"),
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
					"caFile": tlsCA,
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIPullFailedReason, "failed to determine artifact digest"),
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
					"caFile": []byte("invalid"),
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIPullFailedReason, "failed to determine artifact digest"),
			},
		},
		{
			name:        "with contextual login provider",
			wantErr:     true,
			provider:    "aws",
			providerImg: "oci://123456789000.dkr.ecr.us-east-2.amazonaws.com/test",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, "failed to get credential from"),
			},
		},
		{
			name: "with contextual login provider and secretRef",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			craneOpts: []crane.Option{crane.WithAuth(&authn.Basic{
				Username: testRegistryUsername,
				Password: testRegistryPassword,
			})},
			secretOpts: secretOptions{
				username:      testRegistryUsername,
				password:      testRegistryPassword,
				includeSecret: true,
			},
			provider: "azure",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-strategy-",
				},
				Spec: sourcev1.OCIRepositorySpec{
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
				},
			}

			workspaceDir := t.TempDir()
			server, err := setupRegistryServer(ctx, workspaceDir, tt.registryOpts)

			g.Expect(err).NotTo(HaveOccurred())

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

				builder.WithObjects(secret)

				if tt.secretOpts.includeSA {
					serviceAccount := &corev1.ServiceAccount{
						ObjectMeta: metav1.ObjectMeta{
							Name: "sa-ocitest",
						},
						ImagePullSecrets: []corev1.LocalObjectReference{{Name: secret.Name}},
					}
					builder.WithObjects(serviceAccount)
					obj.Spec.ServiceAccountName = serviceAccount.Name
				}

				if tt.secretOpts.includeSecret {
					obj.Spec.SecretRef = &meta.LocalObjectReference{
						Name: secret.Name,
					}
				}
			}

			if tt.tlsCertSecret != nil {
				builder.WithObjects(tt.tlsCertSecret)
				obj.Spec.CertSecretRef = &meta.LocalObjectReference{
					Name: tt.tlsCertSecret.Name,
				}
			}

			r := &OCIRepositoryReconciler{
				Client:        builder.Build(),
				EventRecorder: record.NewFakeRecorder(32),
				Storage:       testStorage,
			}

			opts := craneOptions(ctx, true)
			opts = append(opts, crane.WithAuthFromKeychain(authn.DefaultKeychain))
			repoURL, err := r.getArtifactURL(obj, opts)
			g.Expect(err).To(BeNil())

			assertConditions := tt.assertConditions
			for k := range assertConditions {
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<digest>", fmt.Sprintf("%s/%s", img.tag, img.digest.Hex))
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", repoURL)
			}

			tmpDir := t.TempDir()
			got, err := r.reconcileSource(ctx, obj, &sourcev1.Artifact{}, tmpDir)
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

func TestOCIRepository_CertSecret(t *testing.T) {
	g := NewWithT(t)

	srv, rootCertPEM, clientCertPEM, clientKeyPEM, clientTLSCert, err := createTLSServer()
	g.Expect(err).ToNot(HaveOccurred())

	srv.StartTLS()
	defer srv.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}
	// Use the server cert as a CA cert, so the client trusts the
	// server cert. (Only works because the server uses the same
	// cert in both roles).
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	transport.TLSClientConfig.RootCAs = pool
	transport.TLSClientConfig.Certificates = []tls.Certificate{clientTLSCert}

	srv.Client().Transport = transport
	pi, err := createPodinfoImageFromTar("podinfo-6.1.5.tar", "6.1.5", srv.URL, []crane.Option{
		crane.WithTransport(srv.Client().Transport),
	}...)
	g.Expect(err).NotTo(HaveOccurred())

	tlsSecretClientCert := corev1.Secret{
		StringData: map[string]string{
			oci.CACert:     string(rootCertPEM),
			oci.ClientCert: string(clientCertPEM),
			oci.ClientKey:  string(clientKeyPEM),
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
			expectedstatusmessage: fmt.Sprintf("stored artifact for digest '%s'", pi.digest.Hex),
		},
		{
			name:                  "test connection with no secret",
			url:                   pi.url,
			digest:                pi.digest,
			expectreadyconition:   false,
			expectedstatusmessage: "unexpected status code 400 Bad Request: Client sent an HTTP request to an HTTPS server",
		},
		{
			name:   "test connection with with incorrect private key",
			url:    pi.url,
			digest: pi.digest,
			certSecret: &corev1.Secret{
				StringData: map[string]string{
					oci.CACert:     string(rootCertPEM),
					oci.ClientCert: string(clientCertPEM),
					oci.ClientKey:  string("invalid-key"),
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

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "ocirepository-test-resource",
					Namespace:    ns.Name,
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

	podinfoVersions, err := pushMultiplePodinfoImages(server.registryHost, "6.1.4", "6.1.5", "6.1.6")
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
			wantRevision: fmt.Sprintf("latest/%s", img6.digest.Hex),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision"),
			},
		},
		{
			name: "tag reference",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.6",
			},
			want:         sreconcile.ResultSuccess,
			wantRevision: fmt.Sprintf("%s/%s", img6.tag, img6.digest.Hex),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision"),
			},
		},
		{
			name: "semver reference",
			reference: &sourcev1.OCIRepositoryRef{
				SemVer: ">= 6.1.5",
			},
			want:         sreconcile.ResultSuccess,
			wantRevision: fmt.Sprintf("%s/%s", img6.tag, img6.digest.Hex),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision"),
			},
		},
		{
			name: "digest reference",
			reference: &sourcev1.OCIRepositoryRef{
				Digest: img6.digest.String(),
			},
			wantRevision: img6.digest.Hex,
			want:         sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision"),
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
			wantRevision: fmt.Sprintf("%s/%s", img6.tag, img6.digest.Hex),
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision"),
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
			wantRevision: img5.digest.Hex,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision"),
			},
		},
	}

	builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())

	r := &OCIRepositoryReconciler{
		Client:        builder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "checkout-strategy-",
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL:      fmt.Sprintf("oci://%s/podinfo", server.registryHost),
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
				},
			}

			if tt.reference != nil {
				obj.Spec.Reference = tt.reference
			}

			artifact := &sourcev1.Artifact{}
			tmpDir := t.TempDir()
			got, err := r.reconcileSource(ctx, obj, artifact, tmpDir)
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

	tmpDir := t.TempDir()
	server, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	g.Expect(err).ToNot(HaveOccurred())

	podinfoVersions, err := pushMultiplePodinfoImages(server.registryHost, "6.1.4", "6.1.5")
	g.Expect(err).ToNot(HaveOccurred())
	img4 := podinfoVersions["6.1.4"]
	img5 := podinfoVersions["6.1.5"]

	tests := []struct {
		name             string
		reference        *sourcev1.OCIRepositoryRef
		insecure         bool
		digest           string
		want             sreconcile.Result
		wantErr          bool
		wantErrMsg       string
		shouldSign       bool
		keyless          bool
		beforeFunc       func(obj *sourcev1.OCIRepository)
		assertConditions []metav1.Condition
	}{
		{
			name: "signed image should pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			digest:     img4.digest.Hex,
			shouldSign: true,
			want:       sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <digest>"),
			},
		},
		{
			name: "unsigned image should not pass verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.5",
			},
			digest:     img5.digest.Hex,
			wantErr:    true,
			wantErrMsg: "failed to verify the signature using provider 'cosign': no matching signatures were found for '<url>'",
			want:       sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider '<provider>': no matching signatures were found for '<url>'"),
			},
		},
		{
			name: "unsigned image should not pass keyless verification",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.5",
			},
			digest:  img5.digest.Hex,
			wantErr: true,
			want:    sreconcile.ResultEmpty,
			keyless: true,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "failed to verify the signature using provider '<provider> keyless': no matching signatures"),
			},
		},
		{
			name:      "verify failed before, removed from spec, remove condition",
			reference: &sourcev1.OCIRepositoryRef{Tag: "6.1.4"},
			digest:    img4.digest.Hex,
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, "VerifyFailed", "fail msg")
				obj.Spec.Verify = nil
				obj.Status.Artifact = &sourcev1.Artifact{Revision: fmt.Sprintf("%s/%s", img4.tag, img4.digest.Hex)}
			},
			want: sreconcile.ResultSuccess,
		},
		{
			name:       "same artifact, verified before, change in obj gen verify again",
			reference:  &sourcev1.OCIRepositoryRef{Tag: "6.1.4"},
			digest:     img4.digest.Hex,
			shouldSign: true,
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: fmt.Sprintf("%s/%s", img4.tag, img4.digest.Hex)}
				// Set Verified with old observed generation and different reason/message.
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Verified", "verified")
				// Set new object generation.
				obj.SetGeneration(3)
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, meta.SucceededReason, "verified signature of revision <digest>"),
			},
		},
		{
			name:       "no verify for already verified, verified condition remains the same",
			reference:  &sourcev1.OCIRepositoryRef{Tag: "6.1.4"},
			digest:     img4.digest.Hex,
			shouldSign: true,
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				// Artifact present and custom verified condition reason/message.
				obj.Status.Artifact = &sourcev1.Artifact{Revision: fmt.Sprintf("%s/%s", img4.tag, img4.digest.Hex)}
				conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "Verified", "verified")
			},
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.SourceVerifiedCondition, "Verified", "verified"),
			},
		},
		{
			name: "insecure registries are not supported",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.4",
			},
			digest:     img4.digest.Hex,
			shouldSign: true,
			insecure:   true,
			wantErr:    true,
			want:       sreconcile.ResultEmpty,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new revision '<digest>' for '<url>'"),
				*conditions.FalseCondition(sourcev1.SourceVerifiedCondition, sourcev1.VerificationError, "cosign does not support insecure registries"),
			},
		},
	}

	builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())

	r := &OCIRepositoryReconciler{
		Client:        builder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
	}

	pf := func(b bool) ([]byte, error) {
		return []byte("cosign-password"), nil
	}

	keys, err := cosign.GenerateKeyPair(pf)
	g.Expect(err).ToNot(HaveOccurred())

	err = os.WriteFile(path.Join(tmpDir, "cosign.key"), keys.PrivateBytes, 0600)
	g.Expect(err).ToNot(HaveOccurred())

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cosign-key",
		},
		Data: map[string][]byte{
			"cosign.pub": keys.PublicBytes,
		}}

	err = r.Create(ctx, secret)
	if err != nil {
		g.Expect(err).NotTo(HaveOccurred())
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "verify-oci-source-signature-",
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
			}

			if !tt.keyless {
				obj.Spec.Verify.SecretRef = &meta.LocalObjectReference{Name: "cosign-key"}
			}

			if tt.reference != nil {
				obj.Spec.Reference = tt.reference
			}

			keychain, err := r.keychain(ctx, obj)
			if err != nil {
				g.Expect(err).ToNot(HaveOccurred())
			}

			opts := craneOptions(ctx, true)
			opts = append(opts, crane.WithAuthFromKeychain(keychain))
			artifactURL, err := r.getArtifactURL(obj, opts)
			g.Expect(err).ToNot(HaveOccurred())

			if tt.shouldSign {
				ko := coptions.KeyOpts{
					KeyRef:   path.Join(tmpDir, "cosign.key"),
					PassFunc: pf,
				}

				ro := &coptions.RootOptions{
					Timeout: timeout,
				}
				err = sign.SignCmd(ro, ko, coptions.RegistryOptions{Keychain: keychain},
					nil, []string{artifactURL}, "",
					"", true, "",
					"", "", false,
					false, "", false)
				g.Expect(err).ToNot(HaveOccurred())
			}

			assertConditions := tt.assertConditions
			for k := range assertConditions {
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<digest>", fmt.Sprintf("%s/%s", tt.reference.Tag, tt.digest))
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", artifactURL)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<provider>", "cosign")
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			artifact := &sourcev1.Artifact{}
			got, err := r.reconcileSource(ctx, obj, artifact, tmpDir)
			if tt.wantErr {
				tt.wantErrMsg = strings.ReplaceAll(tt.wantErrMsg, "<url>", artifactURL)
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

func TestOCIRepository_reconcileSource_noop(t *testing.T) {
	g := NewWithT(t)

	testRevision := "6.1.5/d1fc4595915714af2492dc4b66097de1e10f80150c8899907d8f8e61c6d6f67d"

	tmpDir := t.TempDir()
	server, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	g.Expect(err).ToNot(HaveOccurred())

	_, err = pushMultiplePodinfoImages(server.registryHost, "6.1.5")
	g.Expect(err).ToNot(HaveOccurred())

	// NOTE: The following verifies if it was a noop run by checking the
	// artifact metadata which is unknown unless the image is pulled.

	tests := []struct {
		name       string
		beforeFunc func(obj *sourcev1.OCIRepository)
		afterFunc  func(g *WithT, artifact *sourcev1.Artifact)
	}{
		{
			name: "full reconcile - no existing artifact",
			afterFunc: func(g *WithT, artifact *sourcev1.Artifact) {
				g.Expect(artifact.Metadata).ToNot(BeEmpty())
			},
		},
		{
			name: "noop - artifact revisions and ccc match",
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: testRevision,
				}
				obj.Status.ContentConfigChecksum = ociRepoEmptyContentConfigChecksum
			},
			afterFunc: func(g *WithT, artifact *sourcev1.Artifact) {
				g.Expect(artifact.Metadata).To(BeEmpty())
			},
		},
		{
			name: "full reconcile - same rev, different ccc",
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.ContentConfigChecksum = "some-checksum"
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
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Operation: sourcev1.OCILayerCopy,
				}
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: testRevision,
				}
				obj.Status.ContentConfigChecksum = "sha256:fcfd705e10431a341f2df5b05ecee1fb54facd9a5e88b0be82276bdf533b6c64"
			},
			afterFunc: func(g *WithT, artifact *sourcev1.Artifact) {
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
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: testRevision,
				}
				obj.Status.ContentConfigChecksum = "sha256:fcfd705e10431a341f2df5b05ecee1fb54facd9a5e88b0be82276bdf533b6c64"
			},
			afterFunc: func(g *WithT, artifact *sourcev1.Artifact) {
				g.Expect(artifact.Metadata).ToNot(BeEmpty())
			},
		},
	}

	builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())
	r := &OCIRepositoryReconciler{
		Client:        builder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "noop-",
				},
				Spec: sourcev1.OCIRepositorySpec{
					URL:       fmt.Sprintf("oci://%s/podinfo", server.registryHost),
					Reference: &sourcev1.OCIRepositoryRef{Tag: "6.1.5"},
					Interval:  metav1.Duration{Duration: interval},
					Timeout:   &metav1.Duration{Duration: timeout},
				},
			}

			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			artifact := &sourcev1.Artifact{}
			tmpDir := t.TempDir()
			got, err := r.reconcileSource(ctx, obj, artifact, tmpDir)
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
		beforeFunc       func(obj *sourcev1.OCIRepository)
		want             sreconcile.Result
		wantErr          bool
		assertArtifact   *sourcev1.Artifact
		assertPaths      []string
		assertConditions []metav1.Condition
		afterFunc        func(g *WithT, obj *sourcev1.OCIRepository)
	}{
		{
			name:       "Archiving Artifact creates correct files and condition",
			targetPath: "testdata/oci/repository",
			artifact: &sourcev1.Artifact{
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
				g.Expect(obj.Status.Artifact.Checksum).To(Equal("de37cb640bfe6c789f2b131416d259747d5757f7fe5e1d9d48f32d8c30af5934"))
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactInStorageCondition, meta.SucceededReason, "stored artifact for digest"),
			},
		},
		{
			name:       "Artifact with source ignore",
			targetPath: "testdata/oci/repository",
			artifact:   &sourcev1.Artifact{Revision: "revision"},
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.Ignore = pointer.String("foo.txt")
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *sourcev1.OCIRepository) {
				g.Expect(obj.Status.Artifact.Checksum).To(Equal("05aada03e3e3e96f5f85a8f31548d833974ce862be14942fb3313eef2df861ec"))
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
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: "revision",
				}
				obj.Status.ContentConfigChecksum = ociRepoEmptyContentConfigChecksum
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
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "revision"}
				obj.Spec.Ignore = pointer.String("aaa")
				obj.Status.ContentConfigChecksum = ociRepoEmptyContentConfigChecksum
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *sourcev1.OCIRepository) {
				g.Expect(obj.Status.ContentConfigChecksum).To(Equal("sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"))
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
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{MediaType: "foo"}
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "revision"}
				obj.Status.ContentConfigChecksum = ociRepoEmptyContentConfigChecksum
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *sourcev1.OCIRepository) {
				g.Expect(obj.Status.ContentConfigChecksum).To(Equal("sha256:82410edf339ab2945d97e26b92b6499e57156db63b94c17654b6ab97fbf86dbb"))
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
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{
					MediaType: "foo",
					Operation: sourcev1.OCILayerCopy,
				}
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "revision"}
				obj.Status.ContentConfigChecksum = ociRepoEmptyContentConfigChecksum
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"latest.tar.gz",
			},
			afterFunc: func(g *WithT, obj *sourcev1.OCIRepository) {
				g.Expect(obj.Status.ContentConfigChecksum).To(Equal("sha256:0e0e1c82f6403c8ee74fdf51349c8b5d98c508b5374c507c7ffb2e41dbc875df"))
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
			beforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.Ignore = pointer.String("aaa")
				obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{MediaType: "foo"}
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "revision"}
				obj.Status.ContentConfigChecksum = "sha256:0b56187b81cab6c3485583a46bec631f5ea08a1f69b769457f0e4aafb47884e3"
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

	builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())

	r := &OCIRepositoryReconciler{
		Client:        builder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "reconcile-artifact-",
				},
			}
			if tt.beforeFunc != nil {
				tt.beforeFunc(obj)
			}

			artifact := &sourcev1.Artifact{}
			if tt.artifact != nil {
				artifact = tt.artifact
			}
			got, err := r.reconcileArtifact(ctx, obj, artifact, tt.targetPath)
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

func TestOCIRepository_getArtifactURL(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	server, err := setupRegistryServer(ctx, tmpDir, registryOptions{})
	g.Expect(err).ToNot(HaveOccurred())

	imgs, err := pushMultiplePodinfoImages(server.registryHost, "6.1.4", "6.1.5", "6.1.6")
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
			want: "ghcr.io/stefanprodan/charts",
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
				Digest: imgs["6.1.6"].digest.Hex,
			},
			want: "ghcr.io/stefanprodan/charts@" + imgs["6.1.6"].digest.Hex,
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
	}

	builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())
	r := &OCIRepositoryReconciler{
		Client:        builder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
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
				},
			}

			if tt.reference != nil {
				obj.Spec.Reference = tt.reference
			}

			opts := craneOptions(ctx, true)
			opts = append(opts, crane.WithAuthFromKeychain(authn.DefaultKeychain))
			got, err := r.getArtifactURL(obj, opts)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestOCIRepository_stalled(t *testing.T) {
	g := NewWithT(t)

	ns, err := testEnv.CreateNamespace(ctx, "ocirepository-stalled-test")
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
			!conditions.IsReady(&resultobj)
	}, timeout).Should(BeTrue())

	// Verify that stalled condition is present in status
	stalledCondition := conditions.Get(&resultobj, meta.StalledCondition)
	g.Expect(stalledCondition).ToNot(BeNil())
	g.Expect(stalledCondition.Reason).Should(Equal(sourcev1.URLInvalidReason))
}

func TestOCIRepository_reconcileStorage(t *testing.T) {
	g := NewWithT(t)

	tests := []struct {
		name             string
		beforeFunc       func(obj *sourcev1.OCIRepository) error
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
		assertArtifact   *sourcev1.Artifact
		assertPaths      []string
	}{
		{
			name: "garbage collects",
			beforeFunc: func(obj *sourcev1.OCIRepository) error {
				revisions := []string{"a", "b", "c", "d"}

				for n := range revisions {
					v := revisions[n]
					obj.Status.Artifact = &sourcev1.Artifact{
						Path:     fmt.Sprintf("/oci-reconcile-storage/%s.txt", v),
						Revision: v,
					}
					if err := testStorage.MkdirAll(*obj.Status.Artifact); err != nil {
						return err
					}

					if err := testStorage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader(v), 0o640); err != nil {
						return err
					}

					if n != len(revisions)-1 {
						time.Sleep(time.Second)
					}
				}

				testStorage.SetArtifactURL(obj.Status.Artifact)
				return nil
			},
			assertArtifact: &sourcev1.Artifact{
				Path:     "/oci-reconcile-storage/d.txt",
				Revision: "d",
				Checksum: "18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
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
		},
		{
			name: "notices missing artifact in storage",
			beforeFunc: func(obj *sourcev1.OCIRepository) error {
				obj.Status.Artifact = &sourcev1.Artifact{
					Path:     "/oci-reconcile-storage/invalid.txt",
					Revision: "e",
				}
				testStorage.SetArtifactURL(obj.Status.Artifact)
				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"!/oci-reconcile-storage/invalid.txt",
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NoArtifact", "no artifact for resource in storage"),
			},
		},
		{
			name: "updates hostname on diff from current",
			beforeFunc: func(obj *sourcev1.OCIRepository) error {
				obj.Status.Artifact = &sourcev1.Artifact{
					Path:     "/oci-reconcile-storage/hostname.txt",
					Revision: "f",
					Checksum: "3b9c358f36f0a31b6ad3e14f309c7cf198ac9246e8316f9ce543d5b19ac02b80",
					URL:      "http://outdated.com/oci-reconcile-storage/hostname.txt",
				}
				if err := testStorage.MkdirAll(*obj.Status.Artifact); err != nil {
					return err
				}
				if err := testStorage.AtomicWriteFile(obj.Status.Artifact, strings.NewReader("file"), 0o640); err != nil {
					return err
				}
				return nil
			},
			want: sreconcile.ResultSuccess,
			assertPaths: []string{
				"/oci-reconcile-storage/hostname.txt",
			},
			assertArtifact: &sourcev1.Artifact{
				Path:     "/oci-reconcile-storage/hostname.txt",
				Revision: "f",
				Checksum: "3b9c358f36f0a31b6ad3e14f309c7cf198ac9246e8316f9ce543d5b19ac02b80",
				URL:      testStorage.Hostname + "/oci-reconcile-storage/hostname.txt",
				Size:     int64p(int64(len("file"))),
			},
		},
	}

	builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())
	r := &OCIRepositoryReconciler{
		Client:        builder.Build(),
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			obj := &sourcev1.OCIRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
				},
			}

			g.Expect(tt.beforeFunc(obj)).To(Succeed())
			got, err := r.reconcileStorage(ctx, obj, &sourcev1.Artifact{}, "")
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
		})
	}
}

func TestOCIRepository_ReconcileDelete(t *testing.T) {
	g := NewWithT(t)

	r := &OCIRepositoryReconciler{
		EventRecorder: record.NewFakeRecorder(32),
		Storage:       testStorage,
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
				obj.Status.Artifact = &sourcev1.Artifact{
					Revision: "xxx",
					Checksum: "yyy",
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
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.ReadOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.URL = "oci://newurl.io"
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal Succeeded stored artifact with revision 'xxx' from 'oci://newurl.io'",
		},
		{
			name:   "recovery and new artifact",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy"}
				conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.ReadOperationFailedReason, "fail")
				conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, "foo")
			},
			newObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Spec.URL = "oci://newurl.io"
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "aaa", Checksum: "bbb"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			wantEvent: "Normal NewArtifact stored artifact with revision 'aaa' from 'oci://newurl.io'",
		},
		{
			name:   "no updates",
			res:    sreconcile.ResultSuccess,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
			newObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy"}
				conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "ready")
			},
		},
		{
			name:   "no updates on requeue",
			res:    sreconcile.ResultRequeue,
			resErr: nil,
			oldObjBeforeFunc: func(obj *sourcev1.OCIRepository) {
				obj.Status.Artifact = &sourcev1.Artifact{Revision: "xxx", Checksum: "yyy"}
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

func pushMultiplePodinfoImages(serverURL string, versions ...string) (map[string]podinfoImage, error) {
	podinfoVersions := make(map[string]podinfoImage)

	for i := 0; i < len(versions); i++ {
		pi, err := createPodinfoImageFromTar(fmt.Sprintf("podinfo-%s.tar", versions[i]), versions[i], serverURL)
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
		oci.RevisionAnnotation: fmt.Sprintf("%s/SHA", tag),
	}
	return mutate.Annotations(img, metadata).(gcrv1.Image)
}

// These two taken verbatim from https://ericchiang.github.io/post/go-tls/
func certTemplate() (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would
	// have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Flux project"}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour), // valid for an hour
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}

func createCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (
	cert *x509.Certificate, certPEM []byte, err error) {

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

func createTLSServer() (*httptest.Server, []byte, []byte, []byte, tls.Certificate, error) {
	var clientTLSCert tls.Certificate
	var rootCertPEM, clientCertPEM, clientKeyPEM []byte

	srv := httptest.NewUnstartedServer(registry.New())

	// Create a self-signed cert to use as the CA and server cert.
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return srv, rootCertPEM, clientCertPEM, clientKeyPEM, clientTLSCert, err
	}
	rootCertTmpl, err := certTemplate()
	if err != nil {
		return srv, rootCertPEM, clientCertPEM, clientKeyPEM, clientTLSCert, err
	}
	rootCertTmpl.IsCA = true
	rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	rootCertTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	var rootCert *x509.Certificate
	rootCert, rootCertPEM, err = createCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return srv, rootCertPEM, clientCertPEM, clientKeyPEM, clientTLSCert, err
	}

	rootKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
	})

	// Create a TLS cert using the private key and certificate.
	rootTLSCert, err := tls.X509KeyPair(rootCertPEM, rootKeyPEM)
	if err != nil {
		return srv, rootCertPEM, clientCertPEM, clientKeyPEM, clientTLSCert, err
	}

	// To trust a client certificate, the server must be given a
	// CA cert pool.
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	srv.TLS = &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{rootTLSCert},
		ClientCAs:    pool,
	}

	// Create a client cert, signed by the "CA".
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return srv, rootCertPEM, clientCertPEM, clientKeyPEM, clientTLSCert, err
	}
	clientCertTmpl, err := certTemplate()
	if err != nil {
		return srv, rootCertPEM, clientCertPEM, clientKeyPEM, clientTLSCert, err
	}
	clientCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	clientCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	_, clientCertPEM, err = createCert(clientCertTmpl, rootCert, &clientKey.PublicKey, rootKey)
	if err != nil {
		return srv, rootCertPEM, clientCertPEM, clientKeyPEM, clientTLSCert, err
	}
	// Encode and load the cert and private key for the client.
	clientKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})
	clientTLSCert, err = tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	return srv, rootCertPEM, clientCertPEM, clientKeyPEM, clientTLSCert, err
}

func TestOCIRepository_calculateContentConfigChecksum(t *testing.T) {
	g := NewWithT(t)
	obj := &sourcev1.OCIRepository{}
	r := &OCIRepositoryReconciler{}

	emptyChecksum := r.calculateContentConfigChecksum(obj)
	g.Expect(emptyChecksum).To(Equal(ociRepoEmptyContentConfigChecksum))

	// Ignore modified.
	obj.Spec.Ignore = pointer.String("some-rule")
	ignoreModChecksum := r.calculateContentConfigChecksum(obj)
	g.Expect(emptyChecksum).ToNot(Equal(ignoreModChecksum))

	// LayerSelector modified.
	obj.Spec.LayerSelector = &sourcev1.OCILayerSelector{
		MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
	}
	mediaTypeChecksum := r.calculateContentConfigChecksum(obj)
	g.Expect(ignoreModChecksum).ToNot(Equal(mediaTypeChecksum))
	obj.Spec.LayerSelector.Operation = sourcev1.OCILayerCopy
	layerCopyChecksum := r.calculateContentConfigChecksum(obj)
	g.Expect(mediaTypeChecksum).ToNot(Equal(layerCopyChecksum))
}
