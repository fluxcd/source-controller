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
	"testing"

	"github.com/darkowlzz/controller-check/status"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kstatus "sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestHelmRepositoryOCIReconciler_Reconcile(t *testing.T) {
	g := NewWithT(t)

	// Login to the registry
	err := testRegistryserver.RegistryClient.Login(testRegistryserver.DockerRegistryHost,
		registry.LoginOptBasicAuth(testUsername, testPassword),
		registry.LoginOptInsecure(true))
	g.Expect(err).NotTo(HaveOccurred())

	ns, err := testEnv.CreateNamespace(ctx, "helmrepository-oci-reconcile-test")
	g.Expect(err).ToNot(HaveOccurred())
	defer func() { g.Expect(testEnv.Delete(ctx, ns)).To(Succeed()) }()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helmrepository-",
			Namespace:    ns.Name,
		},
		Data: map[string][]byte{
			"username": []byte(testUsername),
			"password": []byte(testPassword),
		},
	}

	g.Expect(testEnv.CreateAndWait(ctx, secret)).To(Succeed())

	obj := &sourcev1.HelmRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helmrepository-oci-reconcile-",
			Namespace:    ns.Name,
		},
		Spec: sourcev1.HelmRepositorySpec{
			Interval: metav1.Duration{Duration: interval},
			URL:      testServer.URL(),
			SecretRef: &meta.LocalObjectReference{
				Name: secret.Name,
			},
			Type: sourcev1.HelmRepositoryTypeOCI,
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
	checker := status.NewChecker(testEnv.Client, testEnv.GetScheme(), condns)
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

	// Wait for OCIArtifact to be deleted
	g.Eventually(func() bool {
		if err := testEnv.Get(ctx, key, obj); err != nil {
			return apierrors.IsNotFound(err)
		}
		return false
	}, timeout).Should(BeTrue())

}
