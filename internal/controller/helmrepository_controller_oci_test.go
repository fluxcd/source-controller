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
	"encoding/base64"
	"fmt"
	"strconv"
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	conditionscheck "github.com/fluxcd/pkg/runtime/conditions/check"
	"github.com/fluxcd/pkg/runtime/patch"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	helmv1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/internal/helm/registry"
)

func TestHelmRepositoryOCIReconciler_deleteBeforeFinalizer(t *testing.T) {
	g := NewWithT(t)

	namespaceName := "helmrepo-" + randStringRunes(5)
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
	}
	g.Expect(k8sClient.Create(ctx, namespace)).ToNot(HaveOccurred())
	t.Cleanup(func() {
		g.Expect(k8sClient.Delete(ctx, namespace)).NotTo(HaveOccurred())
	})

	helmrepo := &helmv1.HelmRepository{}
	helmrepo.Name = "test-helmrepo"
	helmrepo.Namespace = namespaceName
	helmrepo.Spec = helmv1.HelmRepositorySpec{
		Interval: metav1.Duration{Duration: interval},
		URL:      "https://example.com",
		Type:     "oci",
	}
	// Add a test finalizer to prevent the object from getting deleted.
	helmrepo.SetFinalizers([]string{"test-finalizer"})
	g.Expect(k8sClient.Create(ctx, helmrepo)).NotTo(HaveOccurred())
	// Add deletion timestamp by deleting the object.
	g.Expect(k8sClient.Delete(ctx, helmrepo)).NotTo(HaveOccurred())

	r := &HelmRepositoryOCIReconciler{
		Client:        k8sClient,
		EventRecorder: record.NewFakeRecorder(32),
	}
	// NOTE: Only a real API server responds with an error in this scenario.
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(helmrepo)})
	g.Expect(err).NotTo(HaveOccurred())
}

func TestHelmRepositoryOCIReconciler_Reconcile(t *testing.T) {
	tests := []struct {
		name       string
		secretType corev1.SecretType
		secretData map[string][]byte
	}{
		{
			name: "valid auth data",
			secretData: map[string][]byte{
				"username": []byte(testRegistryUsername),
				"password": []byte(testRegistryPassword),
			},
		},
		{
			name:       "no auth data",
			secretData: nil,
		},
		{
			name:       "dockerconfigjson Secret",
			secretType: corev1.SecretTypeDockerConfigJson,
			secretData: map[string][]byte{
				".dockerconfigjson": []byte(`{"auths":{"` +
					testRegistryServer.registryHost + `":{"` +
					`auth":"` + base64.StdEncoding.EncodeToString([]byte(testRegistryUsername+":"+testRegistryPassword)) + `"}}}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ns, err := testEnv.CreateNamespace(ctx, "helmrepository-oci-reconcile-test")
			g.Expect(err).ToNot(HaveOccurred())
			defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-",
					Namespace:    ns.Name,
				},
				Data: tt.secretData,
			}
			if tt.secretType != "" {
				secret.Type = tt.secretType
			}

			g.Expect(testEnv.CreateAndWait(ctx, secret)).To(Succeed())

			origObj := &helmv1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-oci-reconcile-",
					Namespace:    ns.Name,
				},
				Spec: helmv1.HelmRepositorySpec{
					Interval: metav1.Duration{Duration: interval},
					URL:      fmt.Sprintf("oci://%s", testRegistryServer.registryHost),
					SecretRef: &meta.LocalObjectReference{
						Name: secret.Name,
					},
					Provider: helmv1.GenericOCIProvider,
					Type:     helmv1.HelmRepositoryTypeOCI,
				},
			}
			obj := origObj.DeepCopy()
			g.Expect(testEnv.Create(ctx, obj)).To(Succeed())

			key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

			// Wait for finalizer to be set
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, obj); err != nil {
					return false
				}
				return len(obj.Finalizers) > 0
			}, timeout).Should(BeTrue())

			// Wait for HelmRepository to be Ready
			waitForSourceReadyWithoutArtifact(ctx, g, obj)

			// Check if the object status is valid.
			condns := &conditionscheck.Conditions{NegativePolarity: helmRepositoryReadyCondition.NegativePolarity}
			checker := conditionscheck.NewChecker(testEnv.Client, condns)
			checker.WithT(g).CheckErr(ctx, obj)

			// kstatus client conformance check.
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

			g.Expect(testEnv.Delete(ctx, obj)).To(Succeed())

			// Wait for HelmRepository to be deleted
			waitForSourceDeletion(ctx, g, obj)

			// Check if a suspended object gets deleted.
			obj = origObj.DeepCopy()
			testSuspendedObjectDeleteWithoutArtifact(ctx, g, obj)
		})
	}
}

func TestHelmRepositoryOCIReconciler_authStrategy(t *testing.T) {
	type secretOptions struct {
		username string
		password string
	}

	tests := []struct {
		name             string
		url              string
		registryOpts     registryOptions
		insecure         bool
		secretOpts       secretOptions
		secret           *corev1.Secret
		certsSecret      *corev1.Secret
		provider         string
		providerImg      string
		want             ctrl.Result
		wantErr          bool
		assertConditions []metav1.Condition
	}{
		{
			name: "HTTP without basic auth",
			want: ctrl.Result{RequeueAfter: interval},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Helm repository is ready"),
			},
		},
		{
			name:     "HTTP with basic auth secret",
			want:     ctrl.Result{RequeueAfter: interval},
			insecure: true,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			secretOpts: secretOptions{
				username: testRegistryUsername,
				password: testRegistryPassword,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-secretref",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Helm repository is ready"),
			},
		},
		{
			name:     "HTTP registry - basic auth with invalid secret",
			want:     ctrl.Result{},
			wantErr:  true,
			insecure: true,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			secretOpts: secretOptions{
				username: "wrong-pass",
				password: "wrong-pass",
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-secretref",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingWithRetryReason, "processing object: new generation"),
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.AuthenticationFailedReason, "failed to login to registry"),
			},
		},
		{
			name:        "with contextual login provider",
			wantErr:     true,
			insecure:    true,
			provider:    "aws",
			providerImg: "oci://123456789000.dkr.ecr.us-east-2.amazonaws.com/test",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingWithRetryReason, "processing object: new generation"),
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.AuthenticationFailedReason, "failed to get credential from"),
			},
		},
		{
			name: "with contextual login provider and secretRef",
			want: ctrl.Result{RequeueAfter: interval},
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			insecure: true,
			secretOpts: secretOptions{
				username: testRegistryUsername,
				password: testRegistryPassword,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-secretref",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{},
			},
			provider: "azure",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Helm repository is ready"),
			},
		},
		{
			name:    "HTTPS With invalid CA cert",
			wantErr: true,
			registryOpts: registryOptions{
				withTLS:            true,
				withClientCertAuth: true,
			},
			secretOpts: secretOptions{
				username: testRegistryUsername,
				password: testRegistryPassword,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-secretref",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{},
			},
			certsSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "certs-secretref",
				},
				Data: map[string][]byte{
					"ca.crt": []byte("invalid caFile"),
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReconcilingCondition, meta.ProgressingWithRetryReason, "processing object: new generation 0 -> 1"),
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.AuthenticationFailedReason, "cannot append certificate into certificate pool: invalid CA certificate"),
			},
		},
		{
			name: "HTTPS With CA cert",
			want: ctrl.Result{RequeueAfter: interval},
			registryOpts: registryOptions{
				withTLS:            true,
				withClientCertAuth: true,
			},
			secretOpts: secretOptions{
				username: testRegistryUsername,
				password: testRegistryPassword,
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-secretref",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{},
			},
			certsSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "certs-secretref",
				},
				Data: map[string][]byte{
					"ca.crt":  tlsCA,
					"tls.crt": clientPublicKey,
					"tls.key": clientPrivateKey,
				},
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Helm repository is ready"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(testEnv.GetScheme()).
				WithStatusSubresource(&helmv1.HelmRepository{})

			workspaceDir := t.TempDir()
			if tt.insecure {
				tt.registryOpts.disableDNSMocking = true
			}
			server, err := setupRegistryServer(ctx, workspaceDir, tt.registryOpts)
			g.Expect(err).NotTo(HaveOccurred())
			t.Cleanup(func() {
				server.Close()
			})

			obj := &helmv1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-strategy-",
					Generation:   1,
				},
				Spec: helmv1.HelmRepositorySpec{
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
					Type:     helmv1.HelmRepositoryTypeOCI,
					Provider: helmv1.GenericOCIProvider,
					URL:      fmt.Sprintf("oci://%s", server.registryHost),
				},
			}

			if tt.provider != "" {
				obj.Spec.Provider = tt.provider
			}
			// If a provider specific image is provided, overwrite existing URL
			// set earlier. It'll fail, but it's necessary to set them because
			// the login check expects the URLs to be of certain pattern.
			if tt.providerImg != "" {
				obj.Spec.URL = tt.providerImg
			}

			if tt.secretOpts.username != "" && tt.secretOpts.password != "" {
				tt.secret.Data[".dockerconfigjson"] = []byte(fmt.Sprintf(`{"auths": {%q: {"username": %q, "password": %q}}}`,
					server.registryHost, tt.secretOpts.username, tt.secretOpts.password))
			}

			if tt.secret != nil {
				clientBuilder.WithObjects(tt.secret)
				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: tt.secret.Name,
				}
			}

			if tt.certsSecret != nil {
				clientBuilder.WithObjects(tt.certsSecret)
				obj.Spec.CertSecretRef = &meta.LocalObjectReference{
					Name: tt.certsSecret.Name,
				}
			}

			r := &HelmRepositoryOCIReconciler{
				Client:                  clientBuilder.Build(),
				EventRecorder:           record.NewFakeRecorder(32),
				RegistryClientGenerator: registry.ClientGenerator,
				patchOptions:            getPatchOptions(helmRepositoryOCIOwnedConditions, "sc"),
			}

			g.Expect(r.Client.Create(ctx, obj)).ToNot(HaveOccurred())
			defer func() {
				g.Expect(r.Client.Delete(ctx, obj)).ToNot(HaveOccurred())
			}()

			sp := patch.NewSerialPatcher(obj, r.Client)
			got, err := r.reconcile(ctx, sp, obj)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))

			// In-progress status condition validity.
			checker := conditionscheck.NewInProgressChecker(r.Client)
			// NOTE: Check the object directly as reconcile() doesn't apply the
			// final patch, the object has unapplied changes.
			checker.DisableFetch = true
			checker.WithT(g).CheckErr(ctx, obj)
		})
	}
}

func TestConditionsDiff(t *testing.T) {
	tests := []struct {
		a, b, want []string
	}{
		{[]string{"a", "b", "c"}, []string{"b", "d"}, []string{"a", "c"}},
		{[]string{"a", "b", "c"}, []string{}, []string{"a", "b", "c"}},
		{[]string{}, []string{"b", "d"}, []string{}},
		{[]string{}, []string{}, []string{}},
		{[]string{"a", "b"}, nil, []string{"a", "b"}},
		{nil, []string{"a", "b"}, []string{}},
		{nil, nil, []string{}},
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(conditionsDiff(tt.a, tt.b)).To(Equal(tt.want))
		})
	}
}
