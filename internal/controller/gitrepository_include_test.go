/*
Copyright 2026 The Flux authors

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
	"context"
	"testing"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/fluxcd/pkg/apis/meta"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"
)

func TestGitRepositoryIncludeMapping(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := runtime.NewScheme()
	g.Expect(sourcev1.AddToScheme(scheme)).To(Succeed())
	newRepo := func(ns, name string, includes ...string) *sourcev1.GitRepository {
		r := &sourcev1.GitRepository{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
		for _, ref := range includes {
			r.Spec.Include = append(r.Spec.Include, sourcev1.GitRepositoryInclude{GitRepositoryRef: meta.LocalObjectReference{Name: ref}})
		}
		return r
	}
	leaf := newRepo("one", "leaf")
	leaf.Status.Artifact = &meta.Artifact{Revision: "same", Digest: "sha256:new"}
	parent := newRepo("one", "parent", "leaf", "leaf")
	otherNS := newRepo("two", "parent", "leaf")
	suspended := newRepo("one", "suspended", "leaf")
	suspended.Spec.Suspend = true
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(leaf, parent, otherNS, suspended).
		WithIndex(&sourcev1.GitRepository{}, indexKeyGitRepositoryInclude, indexGitRepositoryIncludes).Build()
	r := &GitRepositoryReconciler{Client: c}
	request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(parent)}
	g.Expect(indexGitRepositoryIncludes(parent)).To(Equal([]string{"leaf"}))
	g.Expect(r.requestsForIncludeChange(ctx, leaf)).To(Equal([]reconcile.Request{request}))

	// Updating the specification removes old references and adds new ones.
	g.Expect(c.Get(ctx, client.ObjectKeyFromObject(parent), parent)).To(Succeed())
	parent.Spec.Include = newRepo("one", "parent", "replacement").Spec.Include
	g.Expect(c.Update(ctx, parent)).To(Succeed())
	g.Expect(r.requestsForIncludeChange(ctx, leaf)).To(BeEmpty())
	replacement := newRepo("one", "replacement")
	replacement.Status.Artifact = leaf.Status.Artifact.DeepCopy()
	g.Expect(r.requestsForIncludeChange(ctx, replacement)).To(Equal([]reconcile.Request{request}))
	replacement.Status.Artifact = nil
	g.Expect(r.requestsForIncludeChange(ctx, replacement)).To(BeEmpty())
}

func TestGitRepositoryIncludeCycles(t *testing.T) {
	for _, size := range []int{1, 2, 3} {
		t.Run(string(rune('0'+size)), func(t *testing.T) {
			g := NewWithT(t)
			scheme := runtime.NewScheme()
			g.Expect(sourcev1.AddToScheme(scheme)).To(Succeed())
			var objs []client.Object
			for i := 0; i < size; i++ {
				objs = append(objs, &sourcev1.GitRepository{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: string(rune('a' + i))},
					Spec:       sourcev1.GitRepositorySpec{Include: []sourcev1.GitRepositoryInclude{{GitRepositoryRef: meta.LocalObjectReference{Name: string(rune('a' + (i+1)%size))}}}},
					Status:     sourcev1.GitRepositoryStatus{Artifact: &meta.Artifact{Revision: "same", Digest: "sha256:new"}},
				})
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
				WithIndex(&sourcev1.GitRepository{}, indexKeyGitRepositoryInclude, indexGitRepositoryIncludes).Build()
			r := &GitRepositoryReconciler{Client: c}
			for _, obj := range objs {
				g.Expect(r.requestsForIncludeChange(context.Background(), obj)).To(BeEmpty())
			}
		})
	}
}
