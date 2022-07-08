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
	"testing"
	"time"

	"github.com/darkowlzz/controller-check/status"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/untar"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestOCIRepository_Reconcile(t *testing.T) {
	g := NewWithT(t)

	// Registry server with public images
	regServer := httptest.NewServer(registry.New())
	versions := []string{"6.1.4", "6.1.5", "6.1.6"}
	podinfoVersions := make(map[string]podinfoImage)

	for i := 0; i < len(versions); i++ {
		pi, err := createPodinfoImageFromTar(fmt.Sprintf("podinfo-%s.tar", versions[i]), versions[i], regServer)
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

			t.Log(obj.Spec.Reference)

			// Check if the revision matches the expected digest
			g.Expect(obj.Status.Artifact.Revision).To(Equal(tt.digest))

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

func TestOCIRepository_SecretRef(t *testing.T) {
	g := NewWithT(t)

	// Instantiate Authenticated Registry Server
	regServer, err := setupRegistryServer(ctx)
	g.Expect(err).ToNot(HaveOccurred())

	// Create Test Image
	image, err := crane.Load(path.Join("testdata", "podinfo", "podinfo-6.1.6.tar"))
	g.Expect(err).ToNot(HaveOccurred())

	repositoryURL := fmt.Sprintf("%s/podinfo", regServer.registryHost)
	ociURL := fmt.Sprintf("oci://%s", repositoryURL)

	// Push Test Image
	err = crane.Push(image, repositoryURL, crane.WithAuth(&authn.Basic{
		Username: testRegistryUsername,
		Password: testRegistryPassword,
	}))
	g.Expect(err).ToNot(HaveOccurred())

	// Test Image digest
	podinfoImageDigest, err := image.Digest()
	g.Expect(err).ToNot(HaveOccurred())

	tests := []struct {
		name                  string
		url                   string
		digest                v1.Hash
		includeSecretRef      bool
		includeServiceAccount bool
	}{
		{
			name:                  "private-registry-access-via-secretref",
			url:                   ociURL,
			digest:                podinfoImageDigest,
			includeSecretRef:      true,
			includeServiceAccount: false,
		},
		{
			name:                  "private-registry-access-via-serviceaccount",
			url:                   ociURL,
			digest:                podinfoImageDigest,
			includeSecretRef:      false,
			includeServiceAccount: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ns, err := testEnv.CreateNamespace(ctx, "ocirepository-test")
			g.Expect(err).ToNot(HaveOccurred())
			defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-secretref",
					Namespace:    ns.Name,
				},
				Type: corev1.SecretTypeDockerConfigJson,
				StringData: map[string]string{
					".dockerconfigjson": fmt.Sprintf(`{"auths": {%q: {"username": %q, "password": %q}}}`, repositoryURL, testRegistryUsername, testRegistryPassword),
				},
			}
			g.Expect(testEnv.CreateAndWait(ctx, secret)).To(Succeed())
			defer func() { g.Expect(testEnv.Delete(ctx, secret)).To(Succeed()) }()

			serviceAccount := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "sa-ocitest",
					Namespace:    ns.Name,
				},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: secret.Name}},
			}
			g.Expect(testEnv.CreateAndWait(ctx, serviceAccount)).To(Succeed())
			defer func() { g.Expect(testEnv.Delete(ctx, serviceAccount)).To(Succeed()) }()

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

			if tt.includeSecretRef {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: secret.Name}
			}

			if tt.includeServiceAccount {
				obj.Spec.ServiceAccountName = serviceAccount.Name
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

			t.Log(obj.Status.Artifact.Revision)

			// Check if the revision matches the expected digest
			g.Expect(obj.Status.Artifact.Revision).To(Equal(tt.digest.Hex))

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

			expectedFile := filepath.Join(tmp, `kustomize/deployment.yaml`)
			g.Expect(expectedFile).To(BeAnExistingFile())

			f2, err := os.Open(expectedFile)
			g.Expect(err).ToNot(HaveOccurred())
			defer f2.Close()

			h := testStorage.Checksum(f2)
			t.Logf("hash: %q", h)
			g.Expect(h).To(Equal("6fd625effe6bb805b6a78943ee082a4412e763edb7fcaed6e8fe644d06cbf423"))

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

func TestOCIRepository_FailedAuth(t *testing.T) {
	g := NewWithT(t)

	// Instantiate Authenticated Registry Server
	regServer, err := setupRegistryServer(ctx)
	g.Expect(err).ToNot(HaveOccurred())

	// Create Test Image
	image, err := crane.Load(path.Join("testdata", "podinfo", "podinfo-6.1.6.tar"))
	g.Expect(err).ToNot(HaveOccurred())

	repositoryURL := fmt.Sprintf("%s/podinfo", regServer.registryHost)
	ociURL := fmt.Sprintf("oci://%s", repositoryURL)

	// Push Test Image
	err = crane.Push(image, repositoryURL, crane.WithAuth(&authn.Basic{
		Username: testRegistryUsername,
		Password: testRegistryPassword,
	}))
	g.Expect(err).ToNot(HaveOccurred())

	// Test Image digest
	podinfoImageDigest, err := image.Digest()
	g.Expect(err).ToNot(HaveOccurred())

	tests := []struct {
		name                  string
		url                   string
		digest                v1.Hash
		repoUsername          string
		repoPassword          string
		includeSecretRef      bool
		includeServiceAccount bool
	}{
		{
			name:                  "missing-auth",
			url:                   ociURL,
			repoUsername:          "",
			repoPassword:          "",
			digest:                podinfoImageDigest,
			includeSecretRef:      false,
			includeServiceAccount: false,
		},
		{
			name:                  "invalid-auth-via-secret",
			url:                   ociURL,
			repoUsername:          "InvalidUser",
			repoPassword:          "InvalidPassword",
			digest:                podinfoImageDigest,
			includeSecretRef:      true,
			includeServiceAccount: false,
		},
		{
			name:                  "invalid-auth-via-service-account",
			url:                   ociURL,
			repoUsername:          "InvalidUser",
			repoPassword:          "InvalidPassword",
			digest:                podinfoImageDigest,
			includeSecretRef:      false,
			includeServiceAccount: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ns, err := testEnv.CreateNamespace(ctx, "ocirepository-test")
			g.Expect(err).ToNot(HaveOccurred())
			defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-secretref",
					Namespace:    ns.Name,
				},
				Type: corev1.SecretTypeDockerConfigJson,
				StringData: map[string]string{
					".dockerconfigjson": fmt.Sprintf(`{"auths": {%q: {"username": %q, "password": %q}}}`, repositoryURL, tt.repoUsername, tt.repoPassword),
				},
			}
			g.Expect(testEnv.CreateAndWait(ctx, secret)).To(Succeed())
			defer func() { g.Expect(testEnv.Delete(ctx, secret)).To(Succeed()) }()

			serviceAccount := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "sa-ocitest",
					Namespace:    ns.Name,
				},
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: secret.Name}},
			}
			g.Expect(testEnv.CreateAndWait(ctx, serviceAccount)).To(Succeed())
			defer func() { g.Expect(testEnv.Delete(ctx, serviceAccount)).To(Succeed()) }()

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

			if tt.includeSecretRef {
				obj.Spec.SecretRef = &meta.LocalObjectReference{Name: secret.Name}
			}

			if tt.includeServiceAccount {
				obj.Spec.ServiceAccountName = serviceAccount.Name
			}

			g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

			key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

			failedObj := sourcev1.OCIRepository{}

			// Wait for the finalizer to be set
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, &failedObj); err != nil {
					return false
				}
				return len(failedObj.Finalizers) > 0
			}, timeout).Should(BeTrue())

			// Wait for the object to fail
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, &failedObj); err != nil {
					return false
				}
				readyCondition := conditions.Get(&failedObj, meta.ReadyCondition)
				if readyCondition == nil {
					return false
				}
				return obj.Generation == readyCondition.ObservedGeneration &&
					!conditions.IsReady(&failedObj)
			}, timeout).Should(BeTrue())

			g.Expect(testEnv.Get(ctx, key, &failedObj)).To(Succeed())
			readyCondition := conditions.Get(&failedObj, meta.ReadyCondition)
			g.Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(readyCondition.Message).Should(ContainSubstring("UNAUTHORIZED: authentication required; [map[Action:pull Class: Name:podinfo Type:repository]]"))

			// Wait for the object to be deleted
			g.Expect(testEnv.Delete(ctx, &failedObj)).To(Succeed())
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, &failedObj); err != nil {
					return apierrors.IsNotFound(err)
				}
				return false
			}, timeout).Should(BeTrue())
		})
	}
}

func TestOCIRepository_CertSecret(t *testing.T) {
	g := NewWithT(t)

	registryServer, err := registry.TLS("localhost")
	g.Expect(err).ToNot(HaveOccurred())
	defer registryServer.Close()

	pi, err := createPodinfoImageFromTar("podinfo-6.1.6.tar", "6.1.6", registryServer)
	g.Expect(err).ToNot(HaveOccurred())

	ca_cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registryServer.Certificate().Raw})
	t.Logf("certdata: %v", string(ca_cert))

	tlsSecretCACert := corev1.Secret{
		StringData: map[string]string{
			CACert: string(ca_cert),
		},
	}

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
	pi2, err := createPodinfoImageFromTar("podinfo-6.1.5.tar", "6.1.5", srv)
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
		digest                v1.Hash
		certSecret            *corev1.Secret
		expectreadyconition   bool
		expectedstatusmessage string
	}{
		{
			name:                  "test connection without CACert",
			url:                   pi.url,
			tag:                   pi.tag,
			digest:                pi.digest,
			certSecret:            nil,
			expectreadyconition:   false,
			expectedstatusmessage: "unexpected status code 400 Bad Request: Client sent an HTTP request to an HTTPS server.",
		},
		{
			name:                  "test connection with CACert",
			url:                   pi.url,
			tag:                   pi.tag,
			digest:                pi.digest,
			certSecret:            &tlsSecretCACert,
			expectreadyconition:   true,
			expectedstatusmessage: fmt.Sprintf("stored artifact for revision '%s'", pi.digest.Hex),
		},
		{
			name:                  "test connection with CACert, Client Cert and Private Key",
			url:                   pi2.url,
			tag:                   pi2.tag,
			digest:                pi2.digest,
			certSecret:            &tlsSecretClientCert,
			expectreadyconition:   true,
			expectedstatusmessage: fmt.Sprintf("stored artifact for revision '%s'", pi2.digest.Hex),
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
	digest v1.Hash
}

func createPodinfoImageFromTar(tarFileName, tag string, imageServer *httptest.Server) (*podinfoImage, error) {
	// Create Image
	image, err := crane.Load(path.Join("testdata", "podinfo", tarFileName))
	if err != nil {
		return nil, err
	}

	url, err := url.Parse(imageServer.URL)
	if err != nil {
		return nil, err
	}
	repositoryURL := fmt.Sprintf("%s/podinfo", url.Host)

	// Image digest
	podinfoImageDigest, err := image.Digest()
	if err != nil {
		return nil, err
	}

	// Push image
	err = crane.Push(image, repositoryURL, crane.WithTransport(imageServer.Client().Transport))

	if err != nil {
		return nil, err
	}

	// Tag the image
	err = crane.Tag(repositoryURL, tag, crane.WithTransport(imageServer.Client().Transport))
	if err != nil {
		return nil, err
	}

	return &podinfoImage{
		url:    "oci://" + repositoryURL,
		tag:    tag,
		digest: podinfoImageDigest,
	}, nil
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

// ----

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
