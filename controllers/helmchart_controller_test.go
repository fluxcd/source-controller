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
	"time"

	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
)

func TestHelmChartReconciler_Reconcile(t *testing.T) {
	g := NewWithT(t)

	sourceObj := &sourcev1.HelmRepository{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helm-chart-reconcile",
			Namespace:    "default",
		},
		Spec: sourcev1.HelmRepositorySpec{
			URL: "https://stefanprodan.github.io/podinfo",
		},
	}
	g.Expect(newTestEnv.Create(ctx, sourceObj)).To(Succeed())

	obj := &sourcev1.HelmChart{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "helmchart-reconcile-",
			Namespace:    "default",
		},
		Spec: sourcev1.HelmChartSpec{
			Chart: "podinfo",
			SourceRef: sourcev1.LocalHelmChartSourceReference{
				Kind: sourcev1.HelmRepositoryKind,
				Name: sourceObj.Name,
			},
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

	// Wait for HelmChart to be Ready
	g.Eventually(func() bool {
		if err := newTestEnv.Get(ctx, key, obj); err != nil {
			return false
		}

		if !conditions.Has(obj, sourcev1.ArtifactAvailableCondition) ||
			!conditions.Has(obj, sourcev1.ChartReconciled) ||
			!conditions.Has(obj, sourcev1.SourceAvailableCondition) ||
			!conditions.Has(obj, meta.ReadyCondition) ||
			conditions.Has(obj, meta.StalledCondition) ||
			conditions.Has(obj, meta.ReconcilingCondition) ||
			obj.Status.Artifact == nil {
			return false
		}

		readyCondition := conditions.Get(obj, meta.ReadyCondition)

		return readyCondition.Status == metav1.ConditionTrue &&
			obj.Generation == readyCondition.ObservedGeneration
	}, timeout, 1*time.Second).Should(BeTrue())

	g.Expect(newTestEnv.Delete(ctx, obj)).To(Succeed())

	// Wait for HelmChart to be deleted
	g.Eventually(func() bool {
		if err := newTestEnv.Get(ctx, key, obj); err != nil {
			return apierrors.IsNotFound(err)
		}
		return false
	}, timeout).Should(BeTrue())
}

func Test_validHelmChartName(t *testing.T) {
	tests := []struct {
		name      string
		chart     string
		expectErr bool
	}{
		{"valid", "drupal", false},
		{"valid dash", "nginx-lego", false},
		{"valid dashes", "aws-cluster-autoscaler", false},
		{"valid alphanum", "ng1nx-leg0", false},
		{"invalid slash", "artifactory/invalid", true},
		{"invalid dot", "in.valid", true},
		{"invalid uppercase", "inValid", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validHelmChartName(tt.chart); (err != nil) != tt.expectErr {
				t.Errorf("validHelmChartName() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}
