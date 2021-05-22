/*
Copyright 2020 The Flux authors

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

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
)

func TestHelmRepositoryReconciler_Reconcile(t *testing.T) {
	g := NewWithT(t)

	obj := &sourcev1.HelmRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helmrepository-reconcile-",
			Namespace:    "default",
		},
		Spec: sourcev1.HelmRepositorySpec{
			URL: "https://stefanprodan.github.io/podinfo",
		},
	}
	g.Expect(newTestEnv.Create(ctx, obj)).To(Succeed())

	key := client.ObjectKey{Name: obj.Name, Namespace: obj.Namespace}

	// Wait for finalizer to be set
	g.Eventually(func() bool {
		if err := newTestEnv.Get(ctx, key, obj); err != nil {
			return false
		}
		return len(obj.Finalizers) > 0
	}, timeout).Should(BeTrue())

	// Wait for HelmRepository to be Ready
	g.Eventually(func() bool {
		if err := newTestEnv.Get(ctx, key, obj); err != nil {
			return false
		}

		if !conditions.Has(obj, sourcev1.ArtifactAvailableCondition) ||
			!conditions.Has(obj, sourcev1.SourceAvailableCondition) ||
			!conditions.Has(obj, meta.ReadyCondition) ||
			obj.Status.Artifact == nil {
			return false
		}

		readyCondition := conditions.Get(obj, meta.ReadyCondition)

		return readyCondition.Status == metav1.ConditionTrue &&
			obj.Generation == readyCondition.ObservedGeneration
	}, timeout).Should(BeTrue())

	g.Expect(newTestEnv.Delete(ctx, obj)).To(Succeed())

	// Wait for HelmRepository to be deleted
	g.Eventually(func() bool {
		if err := newTestEnv.Get(ctx, key, obj); err != nil {
			return apierrors.IsNotFound(err)
		}
		return false
	}, timeout).Should(BeTrue())
}
