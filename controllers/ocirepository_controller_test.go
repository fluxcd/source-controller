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
	"context"
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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/darkowlzz/controller-check/status"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/untar"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestOCIRepository_Reconcile(t *testing.T) {
	g := NewWithT(t)

	// Registry server with public images
	regServer, err := setupRegistryServer(context.Background(), registryOptions{})
	if err != nil {
		t.Fatalf(err.Error())
	}

	versions := []string{"6.1.4", "6.1.5", "6.1.6"}
	podinfoVersions := make(map[string]podinfoImage)

	for i := 0; i < len(versions); i++ {
		pi, err := createPodinfoImageFromTar(fmt.Sprintf("podinfo-%s.tar", versions[i]), versions[i], fmt.Sprintf("http://%s", regServer.registryHost))
		g.Expect(err).ToNot(HaveOccurred())

		podinfoVersions[versions[i]] = *pi

	}

	tests := []struct {
		name           string
		url            string
		tag            string
		semver         string
		digest         string
		assertArtifact []artifactFixture
	}{
		{
			name:   "public tag",
			url:    podinfoVersions["6.1.6"].url,
			tag:    podinfoVersions["6.1.6"].tag,
			digest: podinfoVersions["6.1.6"].digest.Hex,
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
			digest: podinfoVersions["6.1.5"].digest.Hex,
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
			g.Expect(obj.Status.Artifact.Metadata["org.opencontainers.image.source"]).To(ContainSubstring("podinfo"))
			g.Expect(obj.Status.Artifact.Metadata["org.opencontainers.image.revision"]).To(ContainSubstring(tt.tag))

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
		want             sreconcile.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "HTTP without basic auth",
			want: sreconcile.ResultSuccess,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new digest '<digest>' for '<url>'"),
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new digest '<digest>' for '<url>'"),
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
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new digest '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new digest '<digest>' for '<url>'"),
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
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new digest '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new digest '<digest>' for '<url>'"),
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIOperationFailedReason, "failed to pull artifact from "),
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIOperationFailedReason, "failed to pull artifact from "),
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIOperationFailedReason, "failed to pull artifact from "),
			},
		},
		{
			name: "HTTPS with valid certfile",
			want: sreconcile.ResultSuccess,
			registryOpts: registryOptions{
				withTlS: true,
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
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new digest '<digest>' for '<url>'"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new digest '<digest>' for '<url>'"),
			},
		},
		{
			name:    "HTTPS without certfile",
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			registryOpts: registryOptions{
				withTlS: true,
			},
			craneOpts: []crane.Option{crane.WithTransport(&http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pool,
				},
			}),
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIOperationFailedReason, "failed to pull artifact from "),
			},
		},
		{
			name:    "HTTPS with invalid certfile",
			want:    sreconcile.ResultEmpty,
			wantErr: true,
			registryOpts: registryOptions{
				withTlS: true,
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIOperationFailedReason, "failed to pull artifact from "),
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

			server, err := setupRegistryServer(context.Background(), tt.registryOpts)
			g.Expect(err).NotTo(HaveOccurred())

			img, err := createPodinfoImageFromTar("podinfo-6.1.6.tar", "6.1.6", fmt.Sprintf("http://%s", server.registryHost), tt.craneOpts...)
			g.Expect(err).ToNot(HaveOccurred())
			obj.Spec.URL = img.url
			obj.Spec.Reference = &sourcev1.OCIRepositoryRef{
				Tag: img.tag,
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

			repoURL, err := r.getArtifactURL(context.Background(), obj, nil, nil)
			g.Expect(err).To(BeNil())

			assertConditions := tt.assertConditions
			for k := range assertConditions {
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<digest>", img.digest.Hex)
				assertConditions[k].Message = strings.ReplaceAll(assertConditions[k].Message, "<url>", repoURL)
			}

			tmpDir := t.TempDir()
			got, err := r.reconcileSource(context.Background(), obj, &sourcev1.Artifact{}, tmpDir)

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

func TestOCIRepository_reconcileSource_remoteReference(t *testing.T) {
	g := NewWithT(t)

	server, err := setupRegistryServer(context.Background(), registryOptions{})
	g.Expect(err).ToNot(HaveOccurred())

	img5, err := createPodinfoImageFromTar("podinfo-6.1.5.tar", "6.1.5", fmt.Sprintf("http://%s", server.registryHost))
	g.Expect(err).ToNot(HaveOccurred())

	img6, err := createPodinfoImageFromTar("podinfo-6.1.6.tar", "6.1.6", fmt.Sprintf("http://%s", server.registryHost))
	g.Expect(err).ToNot(HaveOccurred())

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
			wantRevision: img6.digest.Hex,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new digest"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new digest"),
			},
		},
		{
			name: "tag reference",
			reference: &sourcev1.OCIRepositoryRef{
				Tag: "6.1.6",
			},
			want:         sreconcile.ResultSuccess,
			wantRevision: img6.digest.Hex,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new digest"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new digest"),
			},
		},
		{
			name: "semver reference",
			reference: &sourcev1.OCIRepositoryRef{
				SemVer: ">= 6.1.5",
			},
			want:         sreconcile.ResultSuccess,
			wantRevision: img6.digest.Hex,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new digest"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new digest"),
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
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new digest"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new digest"),
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
				*conditions.TrueCondition(sourcev1.FetchFailedCondition, sourcev1.OCIOperationFailedReason, "failed to pull artifact"),
			},
		},
		{
			name: "semver should take precedence over tag",
			reference: &sourcev1.OCIRepositoryRef{
				SemVer: ">= 6.1.5",
				Tag:    "6.1.5",
			},
			want:         sreconcile.ResultSuccess,
			wantRevision: img6.digest.Hex,
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new digest"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new digest"),
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
				*conditions.TrueCondition(meta.ReconcilingCondition, "NewRevision", "new digest"),
				*conditions.TrueCondition(sourcev1.ArtifactOutdatedCondition, "NewRevision", "new digest"),
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
			got, err := r.reconcileSource(context.TODO(), obj, artifact, tmpDir)
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
	pi2, err := createPodinfoImageFromTar("podinfo-6.1.5.tar", "6.1.5", srv.URL, []crane.Option{
		crane.WithTransport(srv.Client().Transport),
	}...)
	g.Expect(err).NotTo(HaveOccurred())

	tlsSecretClientCert := corev1.Secret{
		StringData: map[string]string{
			CACert:     string(rootCertPEM),
			ClientCert: string(clientCertPEM),
			ClientKey:  string(clientKeyPEM),
		},
	}

	tests := []struct {
		name                  string
		url                   string
		tag                   string
		digest                gcrv1.Hash
		certSecret            *corev1.Secret
		expectreadyconition   bool
		expectedstatusmessage string
	}{
		{
			name:                  "test connection with CACert, Client Cert and Private Key",
			url:                   pi2.url,
			tag:                   pi2.tag,
			digest:                pi2.digest,
			certSecret:            &tlsSecretClientCert,
			expectreadyconition:   true,
			expectedstatusmessage: fmt.Sprintf("stored artifact for digest '%s'", pi2.digest.Hex),
		},
		{
			name:                  "test connection with with no secret",
			url:                   pi2.url,
			tag:                   pi2.tag,
			digest:                pi2.digest,
			expectreadyconition:   false,
			expectedstatusmessage: "failed to pull artifact",
		},
		{
			name:   "test connection with with incorrect private key",
			url:    pi2.url,
			tag:    pi2.tag,
			digest: pi2.digest,
			certSecret: &corev1.Secret{
				StringData: map[string]string{
					CACert:     string(rootCertPEM),
					ClientCert: string(clientCertPEM),
					ClientKey:  string("invalid-key"),
				},
			},
			expectreadyconition:   false,
			expectedstatusmessage: "failed to generate transport",
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

func setPodinfoImageAnnotations(img gcrv1.Image, tag string) gcrv1.Image {
	metadata := map[string]string{
		"org.opencontainers.image.source":   "https://github.com/stefanprodan/podinfo",
		"org.opencontainers.image.revision": fmt.Sprintf("%s/SHA", tag),
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
