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
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/darkowlzz/controller-check/status"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/internal/helm/registry"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

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

			obj := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "helmrepository-oci-reconcile-",
					Namespace:    ns.Name,
				},
				Spec: sourcev1.HelmRepositorySpec{
					Interval: metav1.Duration{Duration: interval},
					URL:      fmt.Sprintf("oci://%s", testRegistryServer.registryHost),
					SecretRef: &meta.LocalObjectReference{
						Name: secret.Name,
					},
					Provider: sourcev1.GenericOCIProvider,
					Type:     sourcev1.HelmRepositoryTypeOCI,
				},
			}
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

			// Check if the object status is valid.
			condns := &status.Conditions{NegativePolarity: helmRepositoryReadyCondition.NegativePolarity}
			checker := status.NewChecker(testEnv.Client, condns)
			checker.CheckErr(ctx, obj)

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
			g.Eventually(func() bool {
				if err := testEnv.Get(ctx, key, obj); err != nil {
					return apierrors.IsNotFound(err)
				}
				return false
			}, timeout).Should(BeTrue())
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
		secretOpts       secretOptions
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
			name: "HTTP with basic auth secret",
			want: ctrl.Result{RequeueAfter: interval},
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			secretOpts: secretOptions{
				username: testRegistryUsername,
				password: testRegistryPassword,
			},
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Helm repository is ready"),
			},
		},
		{
			name:    "HTTP registry - basic auth with invalid secret",
			want:    ctrl.Result{},
			wantErr: true,
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			secretOpts: secretOptions{
				username: "wrong-pass",
				password: "wrong-pass",
			},
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.AuthenticationFailedReason, "failed to login to registry"),
			},
		},
		{
			name:        "with contextual login provider",
			wantErr:     true,
			provider:    "aws",
			providerImg: "oci://123456789000.dkr.ecr.us-east-2.amazonaws.com/test",
			assertConditions: []metav1.Condition{
				*conditions.FalseCondition(meta.ReadyCondition, sourcev1.AuthenticationFailedReason, "failed to get credential from"),
			},
		},
		{
			name: "with contextual login provider and secretRef",
			want: ctrl.Result{RequeueAfter: interval},
			registryOpts: registryOptions{
				withBasicAuth: true,
			},
			secretOpts: secretOptions{
				username: testRegistryUsername,
				password: testRegistryPassword,
			},
			provider: "azure",
			assertConditions: []metav1.Condition{
				*conditions.TrueCondition(meta.ReadyCondition, meta.SucceededReason, "Helm repository is ready"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			builder := fakeclient.NewClientBuilder().WithScheme(testEnv.GetScheme())
			workspaceDir := t.TempDir()
			server, err := setupRegistryServer(ctx, workspaceDir, tt.registryOpts)
			g.Expect(err).NotTo(HaveOccurred())

			obj := &sourcev1.HelmRepository{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "auth-strategy-",
				},
				Spec: sourcev1.HelmRepositorySpec{
					Interval: metav1.Duration{Duration: interval},
					Timeout:  &metav1.Duration{Duration: timeout},
					Type:     sourcev1.HelmRepositoryTypeOCI,
					Provider: sourcev1.GenericOCIProvider,
					URL:      fmt.Sprintf("oci://%s", server.registryHost),
				},
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

				obj.Spec.SecretRef = &meta.LocalObjectReference{
					Name: secret.Name,
				}
			}

			r := &HelmRepositoryOCIReconciler{
				Client:                  builder.Build(),
				EventRecorder:           record.NewFakeRecorder(32),
				Getters:                 testGetters,
				RegistryClientGenerator: registry.ClientGenerator,
			}

			got, err := r.reconcile(ctx, obj)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
			g.Expect(obj.Status.Conditions).To(conditions.MatchConditions(tt.assertConditions))
		})
	}
}
